package server

import (
	"bytes"
	"crypto"
	"crypto/aes"
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
	"strings"
	"time"
	"unicode"
)

func YeePays(ctx *gin.Context) {
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
	fmt.Println(canonicalRequest)
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

// CurlRequest 易宝支付异步通知接口
// @Summary 易宝支付异步通知接口
// @Tags 易宝支付接口
// @Accept application/json
// @Produce application/json
// @Success 200 {object}  string {"code":200,"data":"正常" ,"msg":"OK"}
// @Router /yeepaycallback [POST]
func YeepayCallback(ctx *gin.Context) {
	response := ctx.PostForm("response")
	customerIdentification := ctx.PostForm("customerIdentification")
	if response == "" || customerIdentification == "" {
		service.RespError(ctx, config.RETURN_CODE_ERROR, config.RETURN_MSG_INTERNALERROR)
		return
	}

	//1.将报文中的 response 按 $ 拆分为 4 个字符串
	f := func(c rune) bool {
		if c == '$' {
			return true
		} else {
			return false
		}
	}
	newResp := strings.FieldsFunc(response, f)

	//2.对第 1 个字符串做 BASE64 解码后，用商户私钥做 RSA 解密，得到对称密钥 randomKey；
	randomKey, _ := PriKeyDecrypt(newResp[0], config.YEEPAY_PRIKEY)

	//3.对第 2 个字符串做 BASE64 解码后，用第 3 个字符串指定的解密算法 AES对称密钥 randomKey 进行解密
	encryptedDataToBase64, _ := base64.RawURLEncoding.DecodeString(newResp[1])
	encryptedData := DecryptAes128Ecb(encryptedDataToBase64, []byte(randomKey))

	//4.上述明文用 $ 分隔为 2 部分，第 1 部分为异步通知明文；第 2 部分为签名。用 YOP 平台公钥和第 4 部分指定的摘要算法（比如 SHA256），做 SHA256withRSA 签名，并与第二部分比较即可验证报文是否为 YOP 平台签发。
	aesD := strings.FieldsFunc(string(encryptedData), f)
	signData := strings.FieldsFunc(aesD[1], unicode.IsSpace)
	err := VerifySignSha256WithRsa(aesD[0], signData[0], config.YEEPAY_PUBKEY)
	if err != nil {
		service.RespError(ctx, config.RETURN_CODE_ERROR, err.Error())
		return
	}
	service.RespSucc(ctx)
}

//AES ECB加密
func DecryptAes128Ecb(data, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(data))
	size := 16
	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}
	return decrypted
}

// 私钥解密
func PriKeyDecrypt(data, privateKey string) (string, error) {
	databs, _ := base64.RawURLEncoding.DecodeString(data)
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)
	rsadata, err := grsa.PriKeyDECRYPT(databs)
	if err != nil {
		return "", err
	}
	return string(rsadata), nil
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

// *rsa.PrivateKey
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

//使用RSAWithSHA256算法签名
func (rsas *RSASecurity) SignSha256WithRsa(data string) (string, error) {
	sha256Hash := sha256.New()
	s_data := []byte(data)
	sha256Hash.Write(s_data)
	hashed := sha256Hash.Sum(nil)

	signByte, err := rsa.SignPKCS1v15(rand.Reader, rsas.prikey, crypto.SHA256, hashed)
	sign := base64.RawURLEncoding.EncodeToString(signByte)
	return string(sign), err
}

// 设置公钥
func getPubKey(publickey []byte) (*rsa.PublicKey, error) {
	// decode public key
	block, _ := pem.Decode(publickey)
	if block == nil {
		return nil, errors.New("get public key error")
	}
	// x509 parse public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), err
}

// *rsa.PublicKey
func (rsas *RSASecurity) GetPublickey() (*rsa.PublicKey, error) {
	return getPubKey([]byte(rsas.pubStr))
}

// 设置公钥
func (rsas *RSASecurity) SetPublicKey(pubStr string) (err error) {
	rsas.pubStr = pubStr
	rsas.pubkey, err = rsas.GetPublickey()
	return err
}

// 公钥加密
func PublicEncrypt(data, publicKey string) (string, error) {

	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)

	rsadata, err := grsa.PubKeyENCTYPT([]byte(data))
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(rsadata), nil
}

// 公钥加密
func (rsas *RSASecurity) PubKeyENCTYPT(input []byte) ([]byte, error) {
	if rsas.pubkey == nil {
		return []byte(""), errors.New(`Please set the public key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(rsas.pubkey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// 使用RSAWithSHA256验证签名
func VerifySignSha256WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha256WithRsa(data, signData)
}

//使用RSAWithSHA256验证签名
func (rsas *RSASecurity) VerifySignSha256WithRsa(data string, signData string) error {
	sign, err := base64.RawURLEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	hash := sha256.New()
	hash.Write([]byte(data))
	return rsa.VerifyPKCS1v15(rsas.pubkey, crypto.SHA256, hash.Sum(nil), sign)
}
