// Docker metadata relay for SPIRE: no Docker mutation or unrestricted inspection.
package main
import("context";"encoding/json";"io";"log";"net";"net/http";"os";"regexp";"strings";"time")
var inspectPath=regexp.MustCompile(`^/(?:v[0-9.]+/)?containers/[a-f0-9]{64}/json$`)
var versionPath=regexp.MustCompile(`^/(?:v[0-9.]+/)?(?:version|_ping)$`)
func main(){
 path:="/relay/docker.sock";_ = os.Remove(path)
 listener,err:=net.Listen("unix",path);if err!=nil{log.Fatal("Metadata socket unavailable")};defer listener.Close();if os.Chmod(path,0600)!=nil{log.Fatal("Socket permissions unavailable")}
 client:=&http.Client{Timeout:3*time.Second,Transport:&http.Transport{DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,"unix","/var/run/docker.sock")}}}
 handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if (r.Method!="GET"&&r.Method!="HEAD")||r.URL.RawQuery!=""||r.URL.RawPath!=""||(!inspectPath.MatchString(r.URL.Path)&&!versionPath.MatchString(r.URL.Path)){http.Error(w,"denied",403);return}
  req,_:=http.NewRequestWithContext(r.Context(),r.Method,"http://docker"+r.URL.Path,nil);res,err:=client.Do(req);if err!=nil{http.Error(w,"metadata unavailable",503);return};defer res.Body.Close()
  b,err:=io.ReadAll(io.LimitReader(res.Body,(1<<20)+1));if err!=nil||len(b)>1<<20||res.StatusCode!=200{http.Error(w,"metadata unavailable",503);return}
  if inspectPath.MatchString(r.URL.Path){
   var data map[string]any;if json.Unmarshal(b,&data)!=nil{http.Error(w,"invalid metadata",503);return}
   config,ok:=data["Config"].(map[string]any);if !ok{http.Error(w,"denied",403);return};labels,ok:=config["Labels"].(map[string]any)
   if !ok||labels["com.docker.compose.project"]!=os.Getenv("LOOM_COMPOSE_PROJECT"){http.Error(w,"denied",403);return}
   // Environment, mounts and host configuration are never disclosed.
   b,_=json.Marshal(map[string]any{"Id":data["Id"],"Image":data["Image"],"State":data["State"],"Config":map[string]any{"Labels":labels,"Image":config["Image"]}})
  }
  for k,v:=range res.Header{if strings.EqualFold(k,"Api-Version")||strings.EqualFold(k,"Docker-Experimental"){w.Header()[k]=v}}
  w.Header().Set("Content-Type",res.Header.Get("Content-Type"));_,_=w.Write(b)
 })
 server:=&http.Server{Handler:handler,ReadHeaderTimeout:2*time.Second,ReadTimeout:5*time.Second,WriteTimeout:5*time.Second}
 log.Fatal(server.Serve(listener))
}
