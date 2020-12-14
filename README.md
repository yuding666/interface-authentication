使用步骤:

(1) 获取appSecret 系统分配的

(2) 使用方式

    //params appSecret 系统分配的加密字符串
    //params Request   请求对象
    //return resp      响应消息体
    //return err       错误消息
    resp,err:=new(interface_authentication.Authentication).HandleRequest(appSecret, Request)

(3) 详情可见demo目录