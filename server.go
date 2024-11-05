package wecom_app_svr

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sbzhu/weworkapi_golang/wxbizmsgcrypt"
	"io"
	"log"
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
	MsgHandler func(*MsgContent)
}

func (was *WecomAppSvr) getHandler(w http.ResponseWriter, req *http.Request) {
	queryValues, parseErr := url.ParseQuery(req.URL.RawQuery)
	if parseErr != nil {
		log.Printf("Error parsing query string: %v", parseErr)
		http.Error(w, parseErr.Error(), http.StatusInternalServerError)
		return
	}
	msgSignature := queryValues.Get("msg_signature")
	timestamp := queryValues.Get("timestamp")
	nonce := queryValues.Get("nonce")
	echostr := queryValues.Get("echostr")

	msgBytes, cryptErr := was.Wxcpt.VerifyURL(msgSignature, timestamp, nonce, echostr)
	if nil != cryptErr {
		log.Printf("DecryptMsg fail: %v", cryptErr)
		http.Error(w, cryptErr.ErrMsg, http.StatusInternalServerError)
		return
	}

	w.Write(msgBytes)
	log.Printf("DecryptMsg successful, decrypted msg is %s", string(msgBytes))
}

func (was *WecomAppSvr) postHandler(w http.ResponseWriter, req *http.Request) {
	queryValues, parseErr := url.ParseQuery(req.URL.RawQuery)
	if parseErr != nil {
		log.Printf("Error parsing query string: %v", parseErr)
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
	//log.Printf("body: %s", string(bodyBytes))

	msgBytes, cryptErr := was.Wxcpt.DecryptMsg(msgSignature, timestamp, nonce, bodyBytes)
	if nil != cryptErr {
		log.Printf("Decrypt body fail: %v", cryptErr)
		http.Error(w, cryptErr.ErrMsg, http.StatusInternalServerError)
		return
	}
	log.Printf("decrypt body:  %s", string(msgBytes))

	var msgContent MsgContent
	unmErr := xml.Unmarshal(msgBytes, &msgContent)
	if nil != unmErr {
		log.Printf("Unmarshal fail")
		http.Error(w, unmErr.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Unmarshal body: %+v", msgContent)
	was.MsgHandler(&msgContent)
	fmt.Fprintf(w, "success")
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Printf("from %s, %s %s", req.RemoteAddr, req.Method, req.RequestURI)
		next.ServeHTTP(w, req)
	})
}

func NewWecomAppSvr(addr string, path string, token string, aesKey string, corpId string, msgHandler func(*MsgContent)) *WecomAppSvr {
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

func Run(port string, path string, token string, aesKey string, corpId string, msgHandler func(*MsgContent)) {
	if port == "" {
		port = "8080"
		log.Printf("port is blank use default port: %s", port)
	}
	was := NewWecomAppSvr(fmt.Sprintf(":%s", port), path, token, aesKey, corpId, msgHandler)
	errChan, err := was.ListenAndServe()
	if err != nil {
		log.Println("web server start failed:", err)
		return
	}
	log.Println("=========>>> web server start ok <<<=========")
	log.Println("=========>>> web server start ok <<<=========")
	log.Println("=========>>> web server start ok <<<=========")

	killChan := make(chan os.Signal, 1)
	signal.Notify(killChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err = <-errChan:
		log.Println("web server run failed:", err)
		return
	case <-killChan:
		log.Println("program is exiting...")
		ctx, cf := context.WithTimeout(context.Background(), time.Second)
		defer cf()
		err = was.Shutdown(ctx)
	}

	if err != nil {
		log.Println("program exit error:", err)
		return
	}

	log.Println("=========>>> program exit ok <<<=========")
	log.Println("=========>>> program exit ok <<<=========")
	log.Println("=========>>> program exit ok <<<=========")
}
