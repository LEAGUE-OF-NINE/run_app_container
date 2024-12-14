use crate::{
    app_container::AppContainerProfile,
    helper::{get_command_line, get_last_error},
    wide_string::WideString,
};
use std::{any::type_name, mem, os::raw::c_void, ptr, ptr::null_mut};
use std::ops::BitOr;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::WIN32_ERROR,
        Security::{
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
            SECURITY_CAPABILITIES,
        },
        Security::Authorization::{
            EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SetEntriesInAclA,
            SetEntriesInAclW, SetNamedSecurityInfoW, GRANT_ACCESS,
            NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SE_OBJECT_TYPE,
            TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_W,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
        System::Threading::{
            CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
            EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
        },
    },
};

#[derive(Debug)]
pub struct IsolatedProcess {
    // TODO: Figure out which fields are needed.
    startup_info: STARTUPINFOEXW,
    process_info: PROCESS_INFORMATION,
    security_capabilities: SECURITY_CAPABILITIES,
    attribute_list_buffer: Vec<u8>,
    application_name: WideString,
    command_line: WideString,
}

impl IsolatedProcess {
    pub fn run(
        executable_path: &String,
        container_folder: &String,
        arguments: &[String],
        app_container_profile: AppContainerProfile,
    ) -> Result<Self, windows::core::Error> {
        let mut process = IsolatedProcess {
            startup_info: STARTUPINFOEXW::default(),
            process_info: PROCESS_INFORMATION::default(),
            security_capabilities: SECURITY_CAPABILITIES::default(),
            attribute_list_buffer: vec![0_u8; Self::get_attribute_list_size()],
            application_name: WideString::from(executable_path),
            command_line: get_command_line(executable_path, arguments),
        };

        log::debug!(
            "{}: executable path: `{}`",
            type_name::<Self>(),
            process.application_name
        );
        log::debug!(
            "{}: command line: `{}`",
            type_name::<Self>(),
            process.command_line
        );

        process.startup_info.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
        process.security_capabilities.AppContainerSid = app_container_profile.sid;
        process.initialise_attribute_list()?;
        process.add_security_capabilities_to_attributes()?;
        process.allow_file_access(container_folder.clone())?;

        // TODO: Launch the process in a job
        process.launch()?;

        Ok(process)
    }

    fn get_attribute_list_size() -> usize {
        let mut attribute_list_size = 0;
        unsafe {
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(null_mut()),
                1,
                0,
                &mut attribute_list_size,
            );
        }
        attribute_list_size
    }

    fn initialise_attribute_list(&mut self) -> Result<(), windows::core::Error> {
        let mut attribute_list_size = self.attribute_list_buffer.len();
        log::debug!(
            "{}: attribute list size is: {:?}",
            type_name::<Self>(),
            attribute_list_size
        );
        self.startup_info.lpAttributeList =
            LPPROC_THREAD_ATTRIBUTE_LIST(self.attribute_list_buffer.as_mut_ptr() as *mut c_void);
        let success = unsafe {
            InitializeProcThreadAttributeList(
                self.startup_info.lpAttributeList,
                1,
                0,
                &mut attribute_list_size,
            )
        };
        if success.as_bool() {
            log::debug!(
                "{}: attribute list: {:?}",
                type_name::<Self>(),
                self.attribute_list_buffer
            );
            Ok(())
        } else {
            Err(get_last_error())
        }
    }

    fn add_security_capabilities_to_attributes(&mut self) -> Result<(), windows::core::Error> {
        let success = unsafe {
            UpdateProcThreadAttribute(
                self.startup_info.lpAttributeList,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
                    .try_into()
                    .unwrap(),
                Some(&self.security_capabilities as *const _ as *const c_void),
                mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        };
        if success.as_bool() {
            Ok(())
        } else {
            Err(get_last_error())
        }
    }

    fn allow_file_access(&mut self, folder: String) -> Result<(), windows::core::Error> {
        let access = EXPLICIT_ACCESS_W {
            grfAccessMode: GRANT_ACCESS,
            grfAccessPermissions: FILE_ALL_ACCESS.0,
            grfInheritance: OBJECT_INHERIT_ACE.bitor(CONTAINER_INHERIT_ACE),
            Trustee: TRUSTEE_W {
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                pMultipleTrustee: null_mut(),
                ptstrName: PWSTR::from_raw(self.security_capabilities.AppContainerSid.0.cast()),
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
            },
        };

        let mut old_acl = null_mut();
        let mut new_acl = null_mut();
        unsafe {
            GetNamedSecurityInfoW(
                PCWSTR::from(&WideString::from(&folder)),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(ptr::addr_of_mut!(old_acl)),
                None,
                null_mut()
            ).ok()?;
            WIN32_ERROR(SetEntriesInAclW(
                Some(&[access]),
                Some(old_acl),
                ptr::addr_of_mut!(new_acl)
            )).ok()?;
            WIN32_ERROR(SetNamedSecurityInfoW(
                PCWSTR::from(&WideString::from(&folder)),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_acl),
                None
            )).ok()?;
        };

        Ok(())
    }

    fn launch(&mut self) -> Result<(), windows::core::Error> {
        let success = unsafe {
            CreateProcessW(
                PCWSTR::from(&self.application_name),
                PWSTR::from(&mut self.command_line),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &self.startup_info.StartupInfo,
                &mut self.process_info,
            )
        };
        if success.as_bool() {
            Ok(())
        } else {
            Err(get_last_error())
        }
    }
}
