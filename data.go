package cos

//接口鉴权响应消息结构体
type InterfaceAuthorizeMsg struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

const (
	SUCCESS_CODE     int = 0     //成功
	ERROR_CODE_ONE   int = 10001 //appId不能为空
	ERROR_CODE_TWO   int = 10002 //signature签名不能为空
	ERROR_CODE_THREE int = 10003 //timestamp不能为空
	ERROR_CODE_FOUR  int = 10004 //nonceStr随机字符串不能为空
	ERROR_CODE_FIVE  int = 10005 //时间戳无效
	ERROR_CODE_SIX   int = 10006 //签名验证失败
)

//每一个切片元素下标对应错误码映射
var indexToStatusCodeMap = map[int]int{
	0: ERROR_CODE_ONE,
	1: ERROR_CODE_TWO,
	2: ERROR_CODE_THREE,
	3: ERROR_CODE_FOUR,
	4: ERROR_CODE_FIVE,
	5: ERROR_CODE_SIX,
}

//状态码对应中文错误消息映射
var statusCodeToDescMap = map[int]string{
	ERROR_CODE_ONE:   "appId lost",
	ERROR_CODE_TWO:   "signature lost",
	ERROR_CODE_THREE: "timestamp lost",
	ERROR_CODE_FOUR:  "nonceStr lost",
	ERROR_CODE_FIVE:  "timestamp invalid",
	ERROR_CODE_SIX:   "signature failed",
}
