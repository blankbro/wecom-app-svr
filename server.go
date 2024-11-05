package wecom_app_svr

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sbzhu/weworkapi_golang/wxbizmsgcrypt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type MsgContent struct {
	FromUsername string `xml:"FromUserName"`
	ToUsername   string `xml:"ToUserName"`
	AgentId      uint32 `xml:"AgentID"`
	CreateTime   uint32 `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	MsgId        string `xml:"MsgId"`

	// 文字
	Content string `xml:"Content"`

	// 图片
	PicUrl  string `xml:"PicUrl"`
	MediaId string `xml:"MediaId"`
}

type WecomAppSvr struct {
	Token      string
	AesKey     string
	CorpId     string
	Path       string
	Srv        *http.Server
	Wxcpt      *wxbizmsgcrypt.WXBizMsgCrypt
	MsgHandler func(MsgContent)
}

func (was *WecomAppSvr) getHandler(w http.ResponseWriter, req *http.Request) {
	queryValues, parseErr := url.ParseQuery(req.URL.RawQuery)
	if parseErr != nil {
		logrus.Infof("Error parsing query string: %v", parseErr)
		http.Error(w, parseErr.Error(), http.StatusInternalServerError)
		return
	}
	msgSignature := queryValues.Get("msg_signature")
	timestamp := queryValues.Get("timestamp")
	nonce := queryValues.Get("nonce")
	echostr := queryValues.Get("echostr")

	msgBytes, cryptErr := was.Wxcpt.VerifyURL(msgSignature, timestamp, nonce, echostr)
	if nil != cryptErr {
		logrus.Infof("DecryptMsg fail: %v", cryptErr)
		http.Error(w, cryptErr.ErrMsg, http.StatusInternalServerError)
		return
	}

	w.Write(msgBytes)
	logrus.Infof("DecryptMsg successful, decrypted msg is %s", string(msgBytes))
}

func (was *WecomAppSvr) postHandler(w http.ResponseWriter, req *http.Request) {
	queryValues, parseErr := url.ParseQuery(req.URL.RawQuery)
	if parseErr != nil {
		logrus.Infof("Error parsing query string: %v", parseErr)
		http.Error(w, parseErr.Error(), http.StatusInternalServerError)
		return
	}
	msgSignature := queryValues.Get("msg_signature")
	timestamp := queryValues.Get("timestamp")
	nonce := queryValues.Get("nonce")
	bodyBytes, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		http.Error(w, readErr.Error(), http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()
	//logrus.Infof("body: %s", string(bodyBytes))

	msgBytes, cryptErr := was.Wxcpt.DecryptMsg(msgSignature, timestamp, nonce, bodyBytes)
	if nil != cryptErr {
		logrus.Infof("Decrypt body fail: %v", cryptErr)
		http.Error(w, cryptErr.ErrMsg, http.StatusInternalServerError)
		return
	}
	logrus.Infof("decrypt body:  %s", string(msgBytes))

	var msgContent MsgContent
	unmErr := xml.Unmarshal(msgBytes, &msgContent)
	if nil != unmErr {
		logrus.Infof("Unmarshal fail")
		http.Error(w, unmErr.Error(), http.StatusInternalServerError)
		return
	}
	logrus.Infof("Unmarshal body: %+v", msgContent)
	go was.MsgHandler(msgContent)
	fmt.Fprintf(w, "success")
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		logrus.Infof("from %s, %s %s", req.RemoteAddr, req.Method, req.RequestURI)
		next.ServeHTTP(w, req)
	})
}

func NewWecomAppSvr(addr string, path string, token string, aesKey string, corpId string, msgHandler func(MsgContent)) *WecomAppSvr {
	was := &WecomAppSvr{
		Token:      token,
		AesKey:     aesKey,
		CorpId:     corpId,
		Srv:        &http.Server{Addr: addr},
		Wxcpt:      wxbizmsgcrypt.NewWXBizMsgCrypt(token, aesKey, corpId, wxbizmsgcrypt.XmlType),
		MsgHandler: msgHandler,
	}

	router := mux.NewRouter()
	router.HandleFunc(path, was.getHandler).Methods("GET")
	router.HandleFunc(path, was.postHandler).Methods("POST")

	was.Srv.Handler = logging(router)
	return was
}

func (was *WecomAppSvr) ListenAndServe() (<-chan error, error) {
	var err error
	errChan := make(chan error)
	go func() {
		err = was.Srv.ListenAndServe()
		errChan <- err
	}()

	select {
	case err = <-errChan:
		return nil, err
	case <-time.After(time.Second):
		return errChan, nil
	}
}

func (was *WecomAppSvr) Shutdown(ctx context.Context) error {
	return was.Srv.Shutdown(ctx)
}

func Run(port string, path string, token string, aesKey string, corpId string, msgHandler func(MsgContent)) {
	if port == "" {
		port = "8080"
		logrus.Infof("port is blank use default port: %s", port)
	}
	was := NewWecomAppSvr(fmt.Sprintf(":%s", port), path, token, aesKey, corpId, msgHandler)
	errChan, err := was.ListenAndServe()
	if err != nil {
		logrus.Fatalf("web server start failed: %v", err)
	}
	logrus.Infof("=========>>> web server start ok <<<=========")
	logrus.Infof("=========>>> web server start ok <<<=========")
	logrus.Infof("=========>>> web server start ok <<<=========")

	killChan := make(chan os.Signal, 1)
	signal.Notify(killChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err = <-errChan:
		logrus.Fatalf("web server run failed: %v", err)
	case <-killChan:
		logrus.Infof("program is exiting...")
		ctx, cf := context.WithTimeout(context.Background(), time.Second)
		defer cf()
		err = was.Shutdown(ctx)
	}

	if err != nil {
		logrus.Fatalf("program exit error: %v", err)
	}

	logrus.Infof("=========>>> program exit ok <<<=========")
	logrus.Infof("=========>>> program exit ok <<<=========")
	logrus.Infof("=========>>> program exit ok <<<=========")
}
