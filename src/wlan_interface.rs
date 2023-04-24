use std::sync::mpsc;

use futures::channel::oneshot;
use get_last_error::Win32Error;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::*;
use windows_sys::Win32::NetworkManagement::WiFi::WlanRegisterNotification as wlan_register_notification;

use crate::utils::callback_executor;
use crate::utils::vary_array_to_vec;
use crate::utils::vary_utf16_to_string;

/// Win32 WLAN API Hander
///
/// # Note
///
/// A WLAN_HANDER is a handle to a WLAN API client. It is used in all subsequent calls to the WLAN API.
/// The handle is obtained by calling the WlanOpenHandle function and is released by calling the WlanCloseHandle function,
/// and those functions will be automatically called on `new` and on `drop`.
///
/// * If any error happened on dropping, it will just be recorded by log and then ignored by the
/// program. *
#[derive(Debug)]
pub struct WlanHander {
    handle: HANDLE,
    negotiated_version: u32,
}

impl Default for WlanHander {
    fn default() -> Self {
        Self::new()
    }
}

impl WlanHander {
    pub fn new() -> Self {
        Self::try_new().unwrap()
    }

    pub fn try_new() -> Result<Self, Win32Error> {
        let mut handle: HANDLE = HANDLE(0);
        let mut negotiated_version: u32 = 0;
        let res = unsafe { WlanOpenHandle(2, None, &mut negotiated_version, &mut handle) };
        if res != 0 {
            let error = Win32Error::new(res);
            log::error!("WlanOpenHandle Error: {}", error);
            return Err(error);
        }
        Ok(Self {
            handle,
            negotiated_version,
        })
    }

    pub(self) fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }
}

impl Drop for WlanHander {
    // automatically close handle when drop
    // if any error happened, log it
    fn drop(&mut self) {
        let res = unsafe { WlanCloseHandle(self.handle, None) };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanCloseHandle Error: {}", err);
        }
    }
}

/// Get all WLAN interfaces from win32 api
pub fn query_system_interfaces(handler: &WlanHander) -> Result<Vec<WlanInterface>, Win32Error> {
    let handler = handler.handle();

    let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    let res = unsafe { WlanEnumInterfaces(handler, None, &mut interface_list) };
    log::debug!("Querying WLAN interfaces...");
    if res != 0 {
        let err = Win32Error::new(res);
        log::error!("WlanEnumInterfaces Error: {}", err);
        return Err(err);
    }
    log::debug!("WLAN interfaces queried successfully.");

    let os_interface_list = match unsafe { interface_list.as_ref() } {
        Some(interface_list) => interface_list,
        None => {
            return Ok(vec![]);
        }
    };
    let item_cnt = os_interface_list.dwNumberOfItems as usize;
    let vary_arr = &os_interface_list.InterfaceInfo;
    let v = unsafe { vary_array_to_vec(item_cnt, vary_arr) };

    log::debug!("WLAN interfaces: {:#?}", v);
    // free memory of interface list
    unsafe {
        WlanFreeMemory(interface_list as _);
    }
    log::debug!("Memory of interface list freed.");

    Ok(v)
}

/// Wrapper for WLAN_INTERFACE_INFO
#[derive(Clone, Debug)]
pub struct WlanInterface {
    interface_guid: GUID,
    interface_description: String,
    state: WlanState,
}
// getters of interface info
impl WlanInterface {
    /// Get the GUID of the interface
    pub fn guid(&self) -> GUID {
        self.interface_guid
    }

    /// Get the description of the interface
    pub fn description(&self) -> &str {
        &self.interface_description
    }

    /// Get the state of the interface
    pub fn state(&self) -> WlanState {
        self.state
    }
}

impl WlanInterface {
    /// Get the connectivity data of the interface
    pub fn connectivity(&self, handle: &WlanHander) -> Result<ConnectivityData, Win32Error> {
        let handle = handle.handle();

        log::debug!(
            "Querying connectivity data of interface: {}",
            self.interface_description
        );

        let mut connectivity_data_size: u32 = 0;
        let mut connectivity_data_ptr = std::ptr::null_mut();

        let res = unsafe {
            WlanQueryInterface(
                handle,
                &self.interface_guid,
                wlan_intf_opcode_current_connection,
                None,
                &mut connectivity_data_size,
                &mut connectivity_data_ptr,
                None,
            )
        };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanQueryInterface Error: {}", err);
            return Err(err);
        }

        log::debug!("Connectivity data queried successfully.");

        let os_connection_attrs =
            unsafe { (connectivity_data_ptr as *const WLAN_CONNECTION_ATTRIBUTES).as_ref() };

        // error is handlered, so the ptr should be non-null, if is null then panic
        let connectivity_data = ConnectivityData::from(
            os_connection_attrs.expect("Cannot acquire connectivity data in interface"),
        );

        log::debug!("Connectivity data: {:#?}", connectivity_data);

        // free memory of WLAN_CONNECTION_ATTRIBUTES
        unsafe {
            WlanFreeMemory(connectivity_data_ptr as _);
        }
        log::debug!("Memory of connectivity data freed.");

        Ok(connectivity_data)
    }

    /// scan for available networks
    pub fn blocking_scan(&self, handle: &WlanHander) -> Result<Vec<BssEntry>, Win32Error> {
        let handle = handle.handle();
        log::debug!("Scanning interface: {}", self.interface_description);
        let res = unsafe { WlanScan(handle, &self.interface_guid, None, None, None) };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanScan Error: {}", err);
            return Err(err);
        }

        let mut notify_token = 0;
        // wait until underlying scan is finished
        let os_notify_data = {
            let (tx, rx) = mpsc::channel::<*mut L2_NOTIFICATION_DATA>();
            let callback = move |data| {
                tx.send(data).unwrap();
            };
            let dyn_closure = Box::new(callback) as Box<dyn FnOnce(*mut L2_NOTIFICATION_DATA)>;
            let closure_ptr = Box::into_raw(Box::new(dyn_closure)) as *mut _;
            log::debug!("Registering callback...");

            let res = unsafe {
                wlan_register_notification(
                    handle.0,
                    WLAN_NOTIFICATION_SOURCE_ACM,
                    true as i32,
                    Some(callback_executor),
                    closure_ptr,
                    core::ptr::null_mut(),
                    &mut notify_token,
                )
            };
            println!(
                "Callback registered successfully. (token: {})",
                notify_token
            );
            if res != 0 {
                let err = Win32Error::new(res);
                log::error!("WlanRegisterNotification Error: {}", err);
                return Err(err);
            }
            rx.recv().unwrap()
        };

        unsafe {
            // todo: check notification data

            // free memory of L2_NOTIFICATION_DATA
            WlanFreeMemory(os_notify_data as _);
            log::debug!("Memory of L2_NOTIFICATION_DATA freed.");

            // unregister notification
            let res = wlan_register_notification(
                handle.0,
                WLAN_NOTIFICATION_SOURCE_NONE,
                false as i32,
                None,
                std::ptr::null(),
                std::ptr::null(),
                &mut notify_token,
            );

            // log if error occurs, but we don't care about the error
            if res != 0 {
                let err = Win32Error::new(res);
                log::error!("WlanRegisterNotification Error: {}", err);
            }
        }
        log::debug!("scan finished.");

        let mut os_bss_list: *mut WLAN_BSS_LIST = std::ptr::null_mut();
        let res = unsafe {
            WlanGetNetworkBssList(
                handle,
                &self.interface_guid,
                None,
                dot11_BSS_type_any,
                false,
                None,
                &mut os_bss_list,
            )
        };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanGetNetworkBssList Error: {}", err);
            return Err(err);
        }

        let bss_list_ref = unsafe { os_bss_list.as_ref() };

        let bss_list = match bss_list_ref {
            Some(bss_list) => {
                let length = bss_list.dwNumberOfItems as usize;
                let bss_list = &bss_list.wlanBssEntries;
                unsafe { vary_array_to_vec(length, bss_list) }
            }
            None => vec![],
        };
        // free memory of WLAN_BSS_LIST
        unsafe { WlanFreeMemory(os_bss_list as _) }
        log::debug!("Memory of WLAN_BSS_LIST freed.");
        Ok(bss_list)
    }

    pub async fn scan(&self, handle: &WlanHander) -> Result<Vec<BssEntry>, Win32Error> {
        let handle = handle.handle();
        log::debug!("Scanning interface: {}", self.interface_description);
        let res = unsafe { WlanScan(handle, &self.interface_guid, None, None, None) };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanScan Error: {}", err);
            return Err(err);
        }

        let mut notify_token = 0;
        // wait until underlying scan is finished
        let os_notify_data = {
            let (tx, rx) = oneshot::channel::<*mut L2_NOTIFICATION_DATA>();
            let callback = move |data| {
                tx.send(data).unwrap();
            };
            let dyn_closure = Box::new(callback) as Box<dyn FnOnce(*mut L2_NOTIFICATION_DATA)>;
            let closure_ptr = Box::into_raw(Box::new(dyn_closure)) as *mut _;

            log::debug!("Registering callback...");
            let res = unsafe {
                wlan_register_notification(
                    handle.0,
                    WLAN_NOTIFICATION_SOURCE_ACM,
                    true as i32,
                    Some(callback_executor),
                    closure_ptr,
                    std::ptr::null(),
                    &mut notify_token,
                )
            };
            if res != 0 {
                let err = Win32Error::new(res);
                log::error!("WlanRegisterNotification Error: {}", err);
                return Err(err);
            }
            println!(
                "Callback registered successfully. (token: {})",
                notify_token
            );
            rx.await.unwrap()
        };

        unsafe {
            // todo: check notification data

            // free memory of L2_NOTIFICATION_DATA
            WlanFreeMemory(os_notify_data as _);
            log::debug!("Memory of L2_NOTIFICATION_DATA freed.");

            let res = wlan_register_notification(
                handle.0,
                WLAN_NOTIFICATION_SOURCE_NONE,
                false as i32,
                None,
                std::ptr::null(),
                std::ptr::null(),
                &mut notify_token,
            );

            // log if error occurs, but we don't care about the error
            if res != 0 {
                let err = Win32Error::new(res);
                log::error!("WlanRegisterNotification Error: {}", err);
            }
        }

        log::debug!("scan finished.");

        let mut os_bss_list: *mut WLAN_BSS_LIST = std::ptr::null_mut();
        let res = unsafe {
            WlanGetNetworkBssList(
                handle,
                &self.interface_guid,
                None,
                dot11_BSS_type_any,
                false,
                None,
                &mut os_bss_list,
            )
        };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanGetNetworkBssList Error: {}", err);
            return Err(err);
        }

        let bss_list_ref = unsafe { os_bss_list.as_ref() };

        let bss_list = match bss_list_ref {
            Some(bss_list) => {
                let length = bss_list.dwNumberOfItems as usize;
                let bss_list = &bss_list.wlanBssEntries;
                unsafe { vary_array_to_vec(length, bss_list) }
            }
            None => vec![],
        };

        // free memory of WLAN_BSS_LIST
        unsafe { WlanFreeMemory(os_bss_list as _) }
        log::debug!("Memory of WLAN_BSS_LIST freed.");
        Ok(bss_list)
    }
}

impl From<&WLAN_INTERFACE_INFO> for WlanInterface {
    fn from(interface: &WLAN_INTERFACE_INFO) -> Self {
        let interface_guid = interface.InterfaceGuid;

        let interface_description = vary_utf16_to_string(&interface.strInterfaceDescription);
        let state = WlanState::from(interface.isState);
        Self {
            interface_guid,
            interface_description,
            state,
        }
    }
}

/// Wrapper for WLAN_IS_STATE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WlanState {
    NotReady,
    Connected,
    AdHocNetworkFormed,
    Disconnecting,
    Disconnected,
    Associating,
    Discovering,
    Authenticating,
}

// that's windows to blame, allow this
#[allow(non_upper_case_globals)]
impl From<WLAN_INTERFACE_STATE> for WlanState {
    fn from(state: WLAN_INTERFACE_STATE) -> Self {
        match state {
            wlan_interface_state_not_ready => Self::NotReady,
            wlan_interface_state_connected => Self::Connected,
            wlan_interface_state_ad_hoc_network_formed => Self::AdHocNetworkFormed,
            wlan_interface_state_disconnecting => Self::Disconnecting,
            wlan_interface_state_disconnected => Self::Disconnected,
            wlan_interface_state_associating => Self::Associating,
            wlan_interface_state_discovering => Self::Discovering,
            wlan_interface_state_authenticating => Self::Authenticating,
            _ => unreachable!(),
        }
    }
}

// that's windows to blame, allow this
#[allow(non_upper_case_globals)]
impl From<WlanState> for WLAN_INTERFACE_STATE {
    fn from(state: WlanState) -> Self {
        match state {
            WlanState::NotReady => wlan_interface_state_not_ready,
            WlanState::Connected => wlan_interface_state_connected,
            WlanState::AdHocNetworkFormed => wlan_interface_state_ad_hoc_network_formed,
            WlanState::Disconnecting => wlan_interface_state_disconnecting,
            WlanState::Disconnected => wlan_interface_state_disconnected,
            WlanState::Associating => wlan_interface_state_associating,
            WlanState::Discovering => wlan_interface_state_discovering,
            WlanState::Authenticating => wlan_interface_state_authenticating,
        }
    }
}

/// Wrapper for WLAN_CONNECTION_ATTRIBUTES
#[derive(Debug)]
pub struct ConnectivityData {
    profile_name: String,
    state: WlanState,
    ssid: String,
    bss_id: String,
    signal_quality: u32,
    rx_rate: u32,
    tx_rate: u32,
}

// getters for ConnectivityData
impl ConnectivityData {
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }
    pub fn state(&self) -> WlanState {
        self.state
    }
    /// Get the SSID of the interface
    ///
    /// for hidden SSID, it will return None
    pub fn ssid(&self) -> Option<&str> {
        if self.ssid.is_empty() {
            None
        } else {
            Some(&self.ssid)
        }
    }
    pub fn bss_id(&self) -> &str {
        &self.bss_id
    }
    pub fn signal_quality(&self) -> u32 {
        self.signal_quality
    }
    pub fn rx_rate(&self) -> u32 {
        self.rx_rate
    }
    pub fn tx_rate(&self) -> u32 {
        self.tx_rate
    }
}

impl From<&WLAN_CONNECTION_ATTRIBUTES> for ConnectivityData {
    fn from(connectivity_data: &WLAN_CONNECTION_ATTRIBUTES) -> Self {
        // this will cause truncation
        let profile_name = vary_utf16_to_string(&connectivity_data.strProfileName);
        let state = WlanState::from(connectivity_data.isState);
        let attrs = &connectivity_data.wlanAssociationAttributes;
        let ssid = unsafe {
            let ssid = attrs.dot11Ssid.ucSSID.as_ptr();
            let len = attrs.dot11Ssid.uSSIDLength as usize;
            let ssid = std::slice::from_raw_parts(ssid, len);

            String::from_utf8(ssid.to_vec()).unwrap()
        };
        let bss_id = attrs.dot11Bssid;
        let bss_id = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bss_id[0], bss_id[1], bss_id[2], bss_id[3], bss_id[4], bss_id[5]
        );
        let signal_quality = attrs.wlanSignalQuality;
        let rx_rate = attrs.ulRxRate;
        let tx_rate = attrs.ulTxRate;

        Self {
            profile_name,
            state,
            ssid,
            bss_id,
            signal_quality,
            rx_rate,
            tx_rate,
        }
    }
}

/// Wrapper for WLAN_BSS_ENTRY
#[derive(Debug, Clone)]
pub struct BssEntry {
    ssid: String,
    bss_id: String,
    rssi: i32,
    link_quality: u32,
    ch_center_frequency: u32,
    rate_set: Vec<f32>,
    // todo: 802.11 information frame
    information_frame: Vec<u8>,
}

// getters for BssEntry
impl BssEntry {
    /// SSID of the BSS network
    ///
    /// For hidden networks, return None
    pub fn ssid(&self) -> Option<&str> {
        if self.ssid.is_empty() {
            None
        } else {
            Some(&self.ssid)
        }
    }
    /// BSS network identifier
    pub fn bss_id(&self) -> &str {
        &self.bss_id
    }
    /// Received signal strength (dBm)
    pub fn rssi(&self) -> i32 {
        self.rssi
    }
    /// Link quality (percentage)
    pub fn link_quality(&self) -> u32 {
        self.link_quality
    }
    /// Center frequency of the channel (MHz)
    pub fn ch_center_frequency(&self) -> u32 {
        self.ch_center_frequency
    }
    /// Rate set of the BSS network (Mbps)
    pub fn rate_set(&self) -> &[f32] {
        &self.rate_set
    }
    /// 802.11 information frame
    ///
    /// TODO: parsing
    pub fn information_frame(&self) -> &[u8] {
        &self.information_frame
    }
}

impl From<&WLAN_BSS_ENTRY> for BssEntry {
    fn from(os_bss_entry: &WLAN_BSS_ENTRY) -> Self {
        let ssid = unsafe {
            let ssid = os_bss_entry.dot11Ssid.ucSSID.as_ptr();
            let len = os_bss_entry.dot11Ssid.uSSIDLength as usize;
            let ssid = std::slice::from_raw_parts(ssid, len);

            String::from_utf8(ssid.to_vec()).unwrap()
        };
        let bss_id = os_bss_entry.dot11Bssid;
        let bss_id = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bss_id[0], bss_id[1], bss_id[2], bss_id[3], bss_id[4], bss_id[5]
        );
        let _phy_type = os_bss_entry.dot11BssPhyType;
        let rssi = os_bss_entry.lRssi;
        let link_quality = os_bss_entry.uLinkQuality;
        let ch_center_frequency = os_bss_entry.ulChCenterFrequency;
        let rate_set = unsafe {
            // get rate_set u16[126] first
            let rate_set: *const u16 = os_bss_entry.wlanRateSet.usRateSet.as_ptr();
            // get rate_set length
            let len = os_bss_entry.wlanRateSet.uRateSetLength as usize;
            let rate_set = std::slice::from_raw_parts(rate_set, len);
            let rate_set = rate_set
                .iter()
                .map(|rate| (*rate & 0x7fff) as f32 / 2.0)
                .collect::<Vec<f32>>();
            rate_set
        };
        let information_frame = unsafe {
            let information_frame = (os_bss_entry as *const WLAN_BSS_ENTRY as *const u8)
                .add(os_bss_entry.ulIeOffset as usize);
            let len = os_bss_entry.ulIeSize as usize;
            let information_frame = std::slice::from_raw_parts(information_frame, len);

            information_frame.to_vec()
        };

        Self {
            ssid,
            bss_id,
            rssi,
            link_quality,
            ch_center_frequency,
            rate_set,
            information_frame,
        }
    }
}
