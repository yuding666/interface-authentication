package cos

import (
	"net/http"
)

//接口鉴权结构体
type Authentication struct {
}

// 处理请求
func (this *Authentication) HandleRequest(appSecret string, request *http.Request) (resp *InterfaceAuthorizeMsg, err error) {
	//接收参数
	query := request.URL.Query()
	signature := query.Get("signature")
	appId := query.Get("appId")
	timestamp := query.Get("timestamp")
	nonceStr := query.Get("nonceStr")

	//初始化响应结构体
	resp = &InterfaceAuthorizeMsg{
		Code: SUCCESS_CODE,
		Msg:  "鉴权成功",
	}

	//参数校验
	if resp, err = paramsCheck(resp, []string{appId, signature, timestamp, nonceStr}); err != nil {
		return resp, err
	}

	//校验时间戳是否是在五分钟内的
	if resp, err = timeStampCheck(resp, timestamp, ""); err != nil {
		return resp, err
	}

	//现在进行签名校验
	resp, err = signatureCheck(resp, map[string]string{
		"appId":     appId,
		"timestamp": timestamp,
		"nonceStr":  nonceStr,
	}, signature, appSecret)
	return resp, err
}
