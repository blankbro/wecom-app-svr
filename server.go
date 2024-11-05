package wecom_app_svr

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sbzhu/weworkapi_golang/wxbizmsgcrypt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
	"wecom-app-svr/internal/server"
)

type WecomAppSvr struct {
	Token  string
	AesKey string
	CorpId string
	Path   string
	Srv    *http.Server
}

func (was *WecomAppSvr) getHandler(w http.ResponseWriter, req *http.Request) {
	queryValues, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		log.Printf("Error parsing query string: %v", err)
		fmt.Fprintf(w, "Error parsing query string: %v", err)
		return
	}
	msg_signature := queryValues.Get("msg_signature")
	timestamp := queryValues.Get("timestamp")
	nonce := queryValues.Get("nonce")
	echostr := queryValues.Get("echostr")

	wxcpt := wxbizmsgcrypt.NewWXBizMsgCrypt(was.Token, was.AesKey, was.CorpId, wxbizmsgcrypt.XmlType)
	msg, cryptErr := wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
	if nil != cryptErr {
		log.Printf("DecryptMsg fail: %v", cryptErr)
		fmt.Fprintf(w, "DecryptMsg fail: %v", cryptErr)
		return
	}

	w.Write(msg)
	decryptedMsg := string(msg)
	log.Printf("DecryptMsg successful, decrypted msg is %s", decryptedMsg)
}

func (was *WecomAppSvr) postHandler(w http.ResponseWriter, req *http.Request) {
}

func NewWecomAppSvr(addr string, path string, token string, aesKey string, corpId string) *WecomAppSvr {
	was := &WecomAppSvr{
		Token:  token,
		AesKey: aesKey,
		CorpId: corpId,
		Srv:    &http.Server{Addr: addr},
	}

	router := mux.NewRouter()
	router.HandleFunc(path, was.getHandler).Methods("GET")
	router.HandleFunc(path, was.postHandler).Methods("POST")

	was.Srv.Handler = server.Logging(router)
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

func Run(port string, path string, token string, aesKey string, corpId string) {
	if port == "" {
		port = "8080"
		log.Printf("port is blank use default port: %s", port)
	}
	was := NewWecomAppSvr(fmt.Sprintf(":%s", port), path, token, aesKey, corpId)
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
