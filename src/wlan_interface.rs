use std::thread;

use get_last_error::Win32Error;
use windows::core::GUID;
use windows::Devices::WiFi::WiFiAdapter;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, wlan_interface_state_ad_hoc_network_formed,
    wlan_interface_state_associating, wlan_interface_state_authenticating,
    wlan_interface_state_connected, wlan_interface_state_disconnected,
    wlan_interface_state_disconnecting, wlan_interface_state_discovering,
    wlan_interface_state_not_ready, wlan_intf_opcode_current_connection, WlanCloseHandle,
    WlanEnumInterfaces, WlanFreeMemory, WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface,
    WlanScan, WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO,
    WLAN_INTERFACE_INFO_LIST, WLAN_INTERFACE_STATE,
};

use crate::utils::vary_array_to_vec;
use crate::utils::vary_utf16_to_string;

/// Win32 WLAN API Hander
///
/// # Note
///
/// A `WLAN_HANDER` is a handle to a WLAN API client. It is used in all subsequent calls to the WLAN API.
/// The handle is obtained by calling the `WlanOpenHandle` function and is released by calling the `WlanCloseHandle` function,
/// and those functions will be automatically called on `new` and on `drop`.
///
/// * If any error happened on dropping, it will just be recorded by log and then ignored by the
/// program. *
#[derive(Debug)]
struct WlanHander {
    handle: HANDLE,
    #[allow(unused)]
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

    #[allow(unused)]
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
pub async fn query_system_interfaces() -> Result<Vec<WlanInterface>, Win32Error> {
    log::debug!("Querying WLAN interfaces...");

    let (res, interface_list) = {
        let handler = WlanHander::new();
        let handler = handler.handle();

        let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let res = unsafe { WlanEnumInterfaces(handler, None, &mut interface_list) };

        (res, interface_list)
    };

    if res != 0 {
        let err = Win32Error::new(res);
        log::error!("WlanEnumInterfaces Error: {}", err);
        return Err(err);
    }

    let mut adapters = WiFiAdapter::FindAllAdaptersAsync()
        .map_err(|e| Win32Error::new(e.code().0 as u32))?
        .await
        .map_err(|e| Win32Error::new(e.code().0 as u32))?
        .into_iter()
        .collect::<Vec<_>>();

    let os_interface_list = match unsafe { interface_list.as_ref() } {
        Some(interface_list) => interface_list,
        None => {
            return Ok(vec![]);
        }
    };
    let item_cnt = os_interface_list.dwNumberOfItems as usize;
    assert_eq!(adapters.len(), item_cnt);

    log::debug!("WLAN interfaces queried successfully.");

    let vary_arr = &os_interface_list.InterfaceInfo;
    let infos: Vec<WlanInterfaceInfo> = unsafe { vary_array_to_vec(item_cnt, vary_arr) };

    let mut interfaces = Vec::with_capacity(item_cnt);
    for info in &infos {
        let guid = info.guid();
        let adapter = {
            let mut adapter = None;
            for (idx, adp) in adapters.iter().enumerate() {
                let nadp = adp.NetworkAdapter().map_err(|e| {
                    log::error!("Error: {:?}", e);
                    Win32Error::new(e.code().0 as u32)
                })?;
                let id = nadp.NetworkAdapterId().map_err(|e| {
                    log::error!("Error: {:?}", e);
                    Win32Error::new(e.code().0 as u32)
                })?;
                if id == guid {
                    let adp = adapters.remove(idx);
                    adapter = Some(adp);
                    break;
                }
            }
            adapter.expect("No adapter found for interface")
        };
        log::debug!("adapter: {:?}", adapter);

        let interface = WlanInterface::new(info.clone(), adapter);
        interfaces.push(interface);
    }

    log::debug!("WLAN interfaces: {:#?}", infos);
    // free memory of interface list
    unsafe {
        WlanFreeMemory(interface_list as _);
    }
    log::debug!("Memory of interface list freed.");

    Ok(interfaces)
}

/// Wrapper for `WLAN_INTERFACE_INFO`
#[derive(Clone, Debug)]
pub struct WlanInterfaceInfo {
    interface_guid: GUID,
    interface_description: String,
    state: WlanState,
}

// getters of interface info
impl WlanInterfaceInfo {
    /// Get the GUID of the interface
    #[must_use]
    pub fn guid(&self) -> GUID {
        self.interface_guid
    }

    /// Get the description of the interface
    #[must_use]
    pub fn description(&self) -> &str {
        &self.interface_description
    }

    /// Get the state of the interface
    #[must_use]
    pub fn state(&self) -> WlanState {
        self.state
    }
}

impl From<&WLAN_INTERFACE_INFO> for WlanInterfaceInfo {
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

#[derive(Debug)]
pub struct WlanInterface {
    info: WlanInterfaceInfo,
    adapter: WiFiAdapter,
}

impl WlanInterface {
    pub fn new(info: WlanInterfaceInfo, adapter: WiFiAdapter) -> Self {
        Self { info, adapter }
    }
    /// Get the GUID of the interface
    pub fn guid(&self) -> GUID {
        self.info.guid()
    }

    /// Get the description of the interface
    pub fn description(&self) -> &str {
        self.info.description()
    }

    /// Get the state of the interface
    pub fn state(&self) -> WlanState {
        self.info.state()
    }
}

impl WlanInterface {
    /// Get the connectivity data of the interface
    pub fn connectivity(&self) -> Result<ConnectivityData, Win32Error> {
        let handle = WlanHander::new();
        let handle = handle.handle();

        log::debug!(
            "Querying connectivity data of interface: {}",
            self.info.interface_description
        );

        let mut connectivity_data_size: u32 = 0;
        let mut connectivity_data_ptr = std::ptr::null_mut();

        let res = unsafe {
            WlanQueryInterface(
                handle,
                &self.guid(),
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
    pub fn blocking_scan(&self) -> Result<Vec<BssEntry>, Win32Error> {
        let handle = WlanHander::new();
        let handle = handle.handle();

        log::debug!("Scanning interface: {}", self.info.interface_description);
        let res = unsafe { WlanScan(handle, &self.info.interface_guid, None, None, None) };
        if res != 0 {
            let err = Win32Error::new(res);
            log::error!("WlanScan Error: {}", err);
            return Err(err);
        }

        // As is mentioned in the win32 wifi documentations,
        // All wifi adapters that meets the need of Windows,
        // must complete the scan within 4 seconds.
        thread::sleep(std::time::Duration::from_secs(4));

        log::debug!("scan finished.");

        let mut os_bss_list: *mut WLAN_BSS_LIST = std::ptr::null_mut();
        let res = unsafe {
            WlanGetNetworkBssList(
                handle,
                &self.info.interface_guid,
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

    pub async fn scan(&self) -> Result<Vec<BssEntry>, Win32Error> {
        log::debug!("Scanning interface: {}", self.info.description());

        self.adapter
            .ScanAsync()
            .map_err(|e| {
                log::error!("ScanAsync Error: {}", e);
                Win32Error::new(e.code().0 as u32)
            })?
            .await
            .map_err(|e| {
                log::error!("ScanAsync Error: {}", e);
                Win32Error::new(e.code().0 as u32)
            })?;

        log::debug!("scan finished.");

        let mut os_bss_list: *mut WLAN_BSS_LIST = std::ptr::null_mut();

        let handle = WlanHander::new();
        let res = unsafe {
            WlanGetNetworkBssList(
                handle.handle(),
                &self.guid(),
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
/// Wrapper for `WLAN_IS_STATE`
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

/// Wrapper for `WLAN_CONNECTION_ATTRIBUTES`
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
    #[must_use]
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }
    #[must_use]
    pub fn state(&self) -> WlanState {
        self.state
    }
    /// Get the SSID of the interface
    ///
    /// for hidden SSID, it will return None
    #[must_use]
    pub fn ssid(&self) -> Option<&str> {
        if self.ssid.is_empty() {
            None
        } else {
            Some(&self.ssid)
        }
    }
    #[must_use]
    pub fn bss_id(&self) -> &str {
        &self.bss_id
    }
    #[must_use]
    pub fn signal_quality(&self) -> u32 {
        self.signal_quality
    }
    #[must_use]
    pub fn rx_rate(&self) -> u32 {
        self.rx_rate
    }
    #[must_use]
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

/// Wrapper for `WLAN_BSS_ENTRY`
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
    #[must_use]
    pub fn ssid(&self) -> Option<&str> {
        if self.ssid.is_empty() {
            None
        } else {
            Some(&self.ssid)
        }
    }
    /// BSS network identifier
    #[must_use]
    pub fn bss_id(&self) -> &str {
        &self.bss_id
    }
    /// Received signal strength (dBm)
    #[must_use]
    pub fn rssi(&self) -> i32 {
        self.rssi
    }
    /// Link quality (percentage)
    #[must_use]
    pub fn link_quality(&self) -> u32 {
        self.link_quality
    }
    /// Center frequency of the channel (`MHz`)
    #[must_use]
    pub fn ch_center_frequency(&self) -> u32 {
        self.ch_center_frequency
    }
    /// Rate set of the BSS network (Mbps)
    #[must_use]
    pub fn rate_set(&self) -> &[f32] {
        &self.rate_set
    }
    /// 802.11 information frame
    ///
    /// TODO: parsing
    #[must_use]
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
                .map(|rate| f32::from(*rate & 0x7fff) / 2.0)
                .collect::<Vec<f32>>();
            rate_set
        };
        let information_frame = unsafe {
            let information_frame = (os_bss_entry as *const WLAN_BSS_ENTRY)
                .cast::<u8>()
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
