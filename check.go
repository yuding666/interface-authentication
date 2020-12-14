package cos

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

//默认时间戳有效期5分钟
const DefaultValidityTime string = "-5m"

//参数校验
func paramsCheck(resp *InterfaceAuthorizeMsg, paramsSli []string) (*InterfaceAuthorizeMsg, error) {
	var err error = nil
	for i, v := range paramsSli {
		if len(v) == 0 {
			resp.Code = indexToStatusCodeMap[i]
			resp.Msg = statusCodeToDescMap[resp.Code]
			err = errors.New(resp.Msg)
			break
		}
	}
	return resp, err
}

/*
 *  时间戳校验
 *  @params resp 响应结构体
 *  @params timestamp 传递的时间戳参数
 *  @params validity 时间戳有效期（传空，默认五分钟）
**/
func timeStampCheck(resp *InterfaceAuthorizeMsg, timeStamp string, validity string) (*InterfaceAuthorizeMsg, error) {
	var err error = nil
	//转为utc时间
	currentUtcTime, beforeFiveUtc := getUtcTimeStamp(validity)
	//将参数时间戳转为int64类型
	timestampInt, _ := strconv.ParseInt(timeStamp, 10, 64)

	//时间戳不在有效时间范围内（当前时间往前推五分钟之内）
	if timestampInt < beforeFiveUtc || timestampInt > currentUtcTime {
		resp.Code = ERROR_CODE_FIVE
		resp.Msg = statusCodeToDescMap[resp.Code]
		err = errors.New(resp.Msg)
	}
	return resp, err
}

//获取utc时间
func getUtcTimeStamp(validity string) (int64, int64) {
	//有效期默认五分钟
	if len(validity) == 0 {
		validity = DefaultValidityTime
	} else {
		validity = fmt.Sprintf("-%vm", validity)
	}
	//获取当前时间字符串
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	//转为utc时间
	currentUtcTime, _ := time.Parse("2006-01-02 15:04:05", currentTime)

	//计算五分钟之前的时间戳
	m, _ := time.ParseDuration(validity)
	beforeFiveUtc := currentUtcTime.Add(m).Unix()
	//返回当前时间的utc时间戳和五分钟之前的时间戳
	return currentUtcTime.Unix(), beforeFiveUtc
}

//签名校验
func signatureCheck(resp *InterfaceAuthorizeMsg, signatureParamsMap map[string]string, signature, appSecret string) (*InterfaceAuthorizeMsg, error) {
	var err error = nil
	//1 将参数按字典顺序排列组合 appId=4mm840188jjm0&nonceStr=345122&timestamp=1408704141
	//因为map类型是无序的，需要将map的键放到切片中进行字典排序，然后取值
	paramsSli := make([]string, 0)
	for k, _ := range signatureParamsMap {
		paramsSli = append(paramsSli, k)
	}
	//对参数进行字典升序排序
	sort.Strings(paramsSli)
	//拼接生成签名对源字符串
	var srcStr string
	for _, paramskey := range paramsSli {
		srcStr += fmt.Sprintf("%v=%v&", paramskey, signatureParamsMap[paramskey])
	}
	srcStr = strings.TrimRight(srcStr, "&")

	data := HmacSHA1(appSecret, srcStr)
	// 用在url中，需要使用URLEncoding
	uEnc := base64.URLEncoding.EncodeToString(data)

	//比对，不一致则签名失败
	if signature != uEnc {
		resp.Code = indexToStatusCodeMap[5]
		resp.Msg = statusCodeToDescMap[resp.Code]
		err = errors.New(resp.Msg)
	}
	return resp, err
}
