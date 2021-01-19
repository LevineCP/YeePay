package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"edu-api/app/config"
	"edu-api/app/service"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"time"
)

func YeePay(ctx *gin.Context) {
	queryType := ctx.PostForm("query")
	apiUrl := ctx.PostForm("apiurl")
	data := map[string]string{
		"parentMerchantNo": "10085853178",
		"merchantNo":       "10085853178",
		"orderId":          "10085853178",
	}
	file := ctx.PostForm("file")
	e := CurlRequest(queryType, apiUrl, file, data)
	service.RespData(ctx, e)
}

// CurlRequest 易宝支付请求签名接口
// @Summary 易宝支付请求签名接口
// @Tags 易宝支付接口
// @Accept application/json
// @Produce application/json
// @Param queryType query string true "请求类型"
// @Param apiUrl query string true "接口名"
// @Param file query string true "上传的文件"
// @Param params query string true "请求的数据"
// @Success 200 {object}  string {"code":200,"data":"正常" ,"msg":"OK"}
// @Router /curlRequest [POST]
func CurlRequest(queryType, apiUrl, file string, params map[string]string) interface{} {

	urlApi := config.YEEPAY_API_URL
	if file != "" {
		//上传文件的接口地址
		urlApi = config.YEEPAY_YOS_API_URL
	}

	//appKey
	appKey := config.PUBLIC_APP_KEY

	//请求日期值
	timeString := fmt.Sprintf("%s", time.Now().Format("2006-01-02 15:04:05"))
	timeStrYmd := timeString[:10]
	timeStrHis := timeString[11:]
	timestamp := timeStrYmd + "T" + timeStrHis + "Z"

	//协议版本
	protocolVersion := "yop-auth-v2"

	//请求签名有效时长
	expiredSeconds := "1800"

	//认证字符串
	authString := protocolVersion + "/" + appKey + "/" + timestamp + "/" + expiredSeconds

	//请求参数
	var dataParams string
	//ksort
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	//拼接
	for _, k := range keys {
		dataParams = dataParams + url.QueryEscape(k) + "=" + url.QueryEscape(params[k]) + "&"
	}
	queryParams := dataParams[0 : len(dataParams)-1]

	//请求头参数
	requestId := service.GetRandomString(32, 0)
	sessionId := service.MD5V(requestId)
	queryHeader := map[string]string{
		"x-yop-request-id": requestId,
	}
	var signedHeaders string
	var signedH string
	//ksort
	var queryKeys []string
	for k := range queryHeader {
		queryKeys = append(queryKeys, k)
	}
	sort.Strings(queryKeys)

	//拼接
	for _, k := range queryKeys {
		signedHeaders = signedHeaders + k + ":" + queryHeader[k] + ";"
		signedH = signedH + k + ";" //+ queryHeader[k] + ";"

	}
	signedHeader := signedHeaders[0 : len(signedHeaders)-1]
	signedHeaderKey := signedH[0 : len(signedH)-1]

	//字符串构建规范请求 CanonicalRequest
	canonicalRequest := authString + "\n" + queryType + "\n" + apiUrl + "\n" + queryParams + "\n" + signedHeader

	//签名
	ySign, err := SignSha256WithRsa(canonicalRequest, config.YEEPAY_PRIKEY)
	signToBase64 := ySign + "$SHA256"

	//
	authorization := "YOP-RSA2048-SHA256 " + authString + "/" + signedHeaderKey + "/" + signToBase64

	client := &http.Client{}
	req, err := http.NewRequest(queryType, urlApi+apiUrl+"?"+queryParams, nil)
	if queryType == "POST" {
		req, err = http.NewRequest(queryType, urlApi+apiUrl, bytes.NewBufferString(queryParams))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	}

	req.Header.Set("authorization", authorization)
	req.Header.Set("x-yop-request-id", requestId)
	req.Header.Set("x-yop-appkey", appKey)
	req.Header.Set("x-yop-sdk-langs", "go")
	req.Header.Set("x-yop-sdk-version", "3.0.0")
	req.Header.Set("x-yop-session-id", sessionId)
	resp, err := client.Do(req)
	if err != nil {
		err.Error()
		return ""
	}

	defer resp.Body.Close()
	respByte, err := ioutil.ReadAll(resp.Body)
	//panic("12345")
	//返回成功
	return string(respByte)
}

type RSASecurity struct {
	pubStr string          //公钥字符串
	priStr string          //私钥字符串
	pubkey *rsa.PublicKey  //公钥
	prikey *rsa.PrivateKey //私钥
}

// 使用RSAWithSHA256算法签名
func SignSha256WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha256WithRsa(data)
	if err != nil {
		return "", err
	}
	return sign, err
}

// *rsa.PublicKey
func (rsas *RSASecurity) GetPrivatekey() (*rsa.PrivateKey, error) {
	return getPriKey([]byte(rsas.priStr))
}

// 设置私钥
func getPriKey(privatekey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatekey)
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}
	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pri2.(*rsa.PrivateKey), nil
}

// 设置私钥
func (rsas *RSASecurity) SetPrivateKey(priStr string) (err error) {
	rsas.priStr = priStr
	rsas.prikey, err = rsas.GetPrivatekey()
	return err
}

/**
 * 使用RSAWithSHA256算法签名
 */
func (rsas *RSASecurity) SignSha256WithRsa(data string) (string, error) {
	sha256Hash := sha256.New()
	s_data := []byte(data)
	sha256Hash.Write(s_data)
	hashed := sha256Hash.Sum(nil)

	signByte, err := rsa.SignPKCS1v15(rand.Reader, rsas.prikey, crypto.SHA256, hashed)
	sign := base64.RawURLEncoding.EncodeToString(signByte)
	return string(sign), err
}
