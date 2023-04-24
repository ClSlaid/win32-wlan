use crate::{vary_array_to_vec, vary_utf16_to_string};
use get_last_error::Win32Error;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::*;

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

/// Wrapper for WLAN_INTERFACE_INFO_LIST

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct InterfaceInfoList {
    interface_infos: Vec<InterfaceInfo>,
}

impl InterfaceInfoList {
    /// Get all WLAN interfaces from win32 api
    pub fn query_system_interfaces(handler: &WlanHander) -> Result<Self, Win32Error> {
        let handler = handler.handle();
        let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let res = unsafe { WlanEnumInterfaces(handler, None, &mut interface_list) };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanEnumInterfaces Error: {}", err);
            return Err(err);
        }
        let interface_infos = unsafe {
            let os_interface_list = match interface_list.as_ref() {
                Some(interface_list) => interface_list,
                None => {
                    let list = vec![];
                    return Ok(Self {
                        interface_infos: list,
                    });
                }
            };
            let item_cnt = os_interface_list.dwNumberOfItems as usize;
            let vary_arr = os_interface_list.InterfaceInfo;
            vary_array_to_vec(item_cnt, vary_arr)
        };

        Ok(Self { interface_infos })
    }

    /// as iterator
    fn iter(&self) -> std::slice::Iter<InterfaceInfo> {
        self.interface_infos.iter()
    }

    /// Get the length of the interface list
    pub fn len(&self) -> usize {
        self.interface_infos.len()
    }
}

/// Wrapper for WLAN_INTERFACE_INFO
#[derive(Clone, Debug)]
pub struct InterfaceInfo {
    interface_guid: GUID,
    interface_description: String,
    state: WlanState,
}
// getters of interface info
impl InterfaceInfo {
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

impl InterfaceInfo {
    /// Get the connectivity data of the interface
    pub fn connectivity(&self, handle: &WlanHander) -> Result<ConnectivityData, Win32Error> {
        let handle = handle.handle();
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

        // error is handlered, so the ptr should be non-null
        let connectivity_data =
            unsafe { connectivity_data_ptr as *const WLAN_CONNECTION_ATTRIBUTES };
        let connectivity_data = ConnectivityData::from(connectivity_data);
        Ok(connectivity_data)
    }

    /// Get interface's GUID, and scan WLAN list, get a list of BSS
    pub fn scan(&self, handle: &WlanHander) -> Result<BssList, Win32Error> {
        let handle = handle.handle();
        let res = unsafe { WlanScan(handle, &self.interface_guid, None, None, None) };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanScan Error: {}", err);
            return Err(err);
        }

        // wait until underlying scan is finished
        std::thread::sleep(std::time::Duration::from_secs(4));

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

        let os_bss_list = unsafe { os_bss_list.as_ref() };

        let bss_list = match os_bss_list {
            Some(bss_list) => BssList::from(bss_list),
            None => BssList::new_empty(),
        };
        Ok(bss_list)
    }
}

impl From<&WLAN_INTERFACE_INFO> for InterfaceInfo {
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
            let ssid = String::from_utf8(ssid.to_vec()).unwrap();
            ssid
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

// from *const WLAN_CONNECTION_ATTRIBUTES to ConnectivityData
// fully read the data, unsafely, from the pointer, to avoid copy and truncate.
// this is safe because the pointer is from the same process
impl From<*const WLAN_CONNECTION_ATTRIBUTES> for ConnectivityData {
    fn from(connectivity_data: *const WLAN_CONNECTION_ATTRIBUTES) -> Self {
        // do not use From<&WLAN_CONNECTION_ATTRIBUTES> for ConnectivityData
        // this will cause truncation
        let profile_name = unsafe {
            let profile_name = (*connectivity_data).strProfileName.as_ptr();
            let len = (*connectivity_data).strProfileName.len();
            let profile_name = std::slice::from_raw_parts(profile_name, len);
            let profile_name = String::from_utf16(profile_name).unwrap();
            let profile_name = profile_name.trim_end_matches(char::from(0)).to_string();
            profile_name
        };
        let state = WlanState::from(unsafe { (*connectivity_data).isState });
        let attrs = unsafe { (*connectivity_data).wlanAssociationAttributes };
        let ssid = unsafe {
            let ssid = attrs.dot11Ssid.ucSSID.as_ptr();
            let len = attrs.dot11Ssid.uSSIDLength as usize;
            let ssid = std::slice::from_raw_parts(ssid, len);
            let ssid = String::from_utf8(ssid.to_vec()).unwrap();
            ssid
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

/// Wrapper for WLAN_BSS_LIST
///
/// Also a iterator of BssEntry
#[derive(Debug)]
pub struct BssList {
    entries: Vec<BssEntry>,
}

impl BssList {
    pub(crate) fn new_empty() -> Self {
        Self { entries: vec![] }
    }

    pub fn iter(&self) -> std::slice::Iter<BssEntry> {
        self.entries.iter()
    }
}

impl From<&WLAN_BSS_LIST> for BssList {
    fn from(bss_list: &WLAN_BSS_LIST) -> Self {
        let entries = vary_array_to_vec(bss_list.dwNumberOfItems as usize, bss_list.wlanBssEntries);
        Self { entries }
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
    pub fn bss_id(&self) -> &str {
        &self.bss_id
    }
    pub fn rssi(&self) -> i32 {
        self.rssi
    }
    pub fn link_quality(&self) -> u32 {
        self.link_quality
    }
    pub fn ch_center_frequency(&self) -> u32 {
        self.ch_center_frequency
    }
    pub fn rate_set(&self) -> &[f32] {
        &self.rate_set
    }
    pub fn information_frame(&self) -> &[u8] {
        &self.information_frame
    }
}

impl From<*const WLAN_BSS_ENTRY> for BssEntry {
    fn from(bss_entry: *const WLAN_BSS_ENTRY) -> Self {
        let ssid = unsafe {
            let ssid = (*bss_entry).dot11Ssid.ucSSID.as_ptr();
            let len = (*bss_entry).dot11Ssid.uSSIDLength as usize;
            let ssid = std::slice::from_raw_parts(ssid, len);
            let ssid = String::from_utf8(ssid.to_vec()).unwrap();
            ssid
        };
        let bss_id = (unsafe { *bss_entry }).dot11Bssid;
        let bss_id = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bss_id[0], bss_id[1], bss_id[2], bss_id[3], bss_id[4], bss_id[5]
        );
        let rssi = (unsafe { *bss_entry }).lRssi;
        let link_quality = (unsafe { *bss_entry }).uLinkQuality;
        let ch_center_frequency = (unsafe { *bss_entry }).ulChCenterFrequency;
        // get rate set from WLAN_RATE_SET
        let rate_set: Vec<u16> = unsafe {
            let rate_set = (*bss_entry).wlanRateSet;
            let rate_set = std::slice::from_raw_parts(
                rate_set.usRateSet.as_ptr(),
                rate_set.uRateSetLength as usize,
            );
            let rate_set = rate_set.to_vec();
            rate_set
        };
        // (rateSet[i] & 0x7FFF) * 0.5
        let rate_set = rate_set
            .into_iter()
            .map(|x| (x & 0x7FFF) as f32 * 0.5)
            .collect();
        let information_frame = unsafe {
            let information_frame = (bss_entry as *const u8).add((*bss_entry).ulIeOffset as usize);
            let len = (*bss_entry).ulIeSize as usize;
            let information_frame = std::slice::from_raw_parts(information_frame, len);
            let information_frame = information_frame.to_vec();
            information_frame
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

impl From<&WLAN_BSS_ENTRY> for BssEntry {
    fn from(os_bss_entry: &WLAN_BSS_ENTRY) -> Self {
        let ssid = unsafe {
            let ssid = os_bss_entry.dot11Ssid.ucSSID.as_ptr();
            let len = os_bss_entry.dot11Ssid.uSSIDLength as usize;
            let ssid = std::slice::from_raw_parts(ssid, len);
            let ssid = String::from_utf8(ssid.to_vec()).unwrap();
            ssid
        };
        let bss_id = os_bss_entry.dot11Bssid;
        let bss_id = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bss_id[0], bss_id[1], bss_id[2], bss_id[3], bss_id[4], bss_id[5]
        );
        let phy_type = os_bss_entry.dot11BssPhyType;
        let rssi = os_bss_entry.lRssi;
        let link_quality = os_bss_entry.uLinkQuality;
        let ch_center_frequency = os_bss_entry.ulChCenterFrequency;
        let rate_set = unsafe {
            // get rate_set u16[126] first
            let rate_set: *const u16 = os_bss_entry.wlanRateSet.usRateSet.as_ptr();
            // get rate_set length
            let len = (*os_bss_entry).wlanRateSet.uRateSetLength as usize;
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
            let information_frame = information_frame.to_vec();
            information_frame
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
