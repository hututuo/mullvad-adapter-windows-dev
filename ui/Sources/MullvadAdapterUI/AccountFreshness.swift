import Foundation

struct DeviceRegistrationStatus: Decodable {
    let state: String?
    let checkedAt: String?
    let message: String?
    let fresh: Bool?
    enum CodingKeys: String, CodingKey { case state, message, fresh; case checkedAt = "checked_at" }
}
struct AccountFreshness: Decodable {
    let signedIn: Bool?
    let state: String?
    let checkedAt: String?
    let lastAttemptAt: String?
    let errorCode: String?
    let apiRoute: String?
    let device: DeviceRegistrationStatus?
    enum CodingKeys: String, CodingKey {
        case state, device; case signedIn = "signed_in", checkedAt = "checked_at", lastAttemptAt = "last_attempt_at"
        case errorCode = "error_code", apiRoute = "api_route"
    }
    var needsAttention: Bool { device?.state == "missing" || state == "error" || state == "signed_out" }
    var summary: String {
        if device?.state == "missing" { return device?.fresh == false ? "上次核实时未找到本机设备，请刷新账号并处理" : "官方列表没有本机设备，请打开账号与设备处理" }
        switch state {
        case "signed_out": return "尚未登录账号管理，可输入账号查看和管理设备"
        case "error": return "官方账号刷新失败，下面的旧资料不代表当前登记状态"
        case "refreshing": return "正在刷新官方设备列表，当前隧道继续运行"
        case "current": return device?.state == "registered" && device?.fresh != false ? "账号已刷新，本机设备仍在官方登记" : "账号已刷新；当前隧道身份需单独核对"
        default: return "官方设备状态待刷新；隧道通断与账号登录分别显示"
        }
    }
    var routeDescription: String {
        switch apiRoute {
        case "configured_proxy": return "独立本机引导代理"
        case "direct_seed", "direct_cached": return "官方地址 HTTPS（保留域名及证书验证）"
        case "system_https": return "系统 HTTPS"
        default: return "尚未确认可用的账号服务出口"
        }
    }
}
struct ConnectionControlStatus: Decodable {
    let stopped: Bool
    let stopOperationID: String?
    let stopError: String?
    enum CodingKeys: String, CodingKey { case stopped; case stopOperationID = "stop_operation_id", stopError = "stop_error" }
}
