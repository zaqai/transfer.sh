/*
The MIT License (MIT)

Copyright (c) 2014-2017 DutchCoders [https://github.com/dutchcoders/]
Copyright (c) 2018-2020 Andrea Spacca.
Copyright (c) 2020- Andrea Spacca and Stefan Benten.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package server

import (
	"encoding/base64"
	"fmt"
	web "github.com/dutchcoders/transfer.sh-web"
	"github.com/dutchcoders/transfer.sh/server/storage"
	"github.com/gorilla/mux"
	"golang.org/x/net/idna"
	htmlTemplate "html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	textTemplate "text/template"
)

const getPathPart = "get"

var (
	htmlTemplates = initHTMLTemplates()
	textTemplates = initTextTemplates()
)

func stripPrefix(path string) string {
	return strings.Replace(path, web.Prefix+"/", "", -1)
}

func initTextTemplates() *textTemplate.Template {
	templateMap := textTemplate.FuncMap{"format": formatNumber}

	// Templates with functions available to them
	var templates = textTemplate.New("").Funcs(templateMap)
	return templates
}

func initHTMLTemplates() *htmlTemplate.Template {
	templateMap := htmlTemplate.FuncMap{"format": formatNumber}

	// Templates with functions available to them
	var templates = htmlTemplate.New("").Funcs(templateMap)

	return templates
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Approaching Neutral Zone, all systems normal and functioning."))
}

/* The preview handler will show a preview of the content for browsers (accept type text/html), and referer is not transfer.sh */
func (s *Server) previewHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	filename := vars["filename"]

	contentLength, err := s.storage.Head(r.Context(), filename)
	if err != nil {
		http.Error(w, http.StatusText(404), 404)
		return
	}

	var templatePath string
	var content htmlTemplate.HTML

	templatePath = "download.html"

	relativeURL, _ := url.Parse(path.Join(s.proxyPath, filename))
	resolvedURL := resolveURL(r, relativeURL, s.proxyPort)
	relativeURLGet, _ := url.Parse(path.Join(s.proxyPath, getPathPart, filename))
	resolvedURLGet := resolveURL(r, relativeURLGet, s.proxyPort)
	var png []byte

	qrCode := base64.StdEncoding.EncodeToString(png)

	hostname := getURL(r, s.proxyPort).Host
	webAddress := resolveWebAddress(r, s.proxyPath, s.proxyPort)

	data := struct {
		Content  htmlTemplate.HTML
		Filename string
		URL      string
		URLGet   string

		Hostname      string
		WebAddress    string
		ContentLength uint64
		GAKey         string
		UserVoiceKey  string
		QRCode        string
	}{

		content,
		filename,
		resolvedURL,
		resolvedURLGet,

		hostname,
		webAddress,
		contentLength,
		s.gaKey,
		s.userVoiceKey,
		qrCode,
	}

	if err := htmlTemplates.ExecuteTemplate(w, templatePath, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

// this handler will output html or text, depending on the
// support of the client (Accept header).

func (s *Server) viewHandler(w http.ResponseWriter, r *http.Request) {
	// vars := mux.Vars(r)

	hostname := getURL(r, s.proxyPort).Host
	webAddress := resolveWebAddress(r, s.proxyPath, s.proxyPort)

	maxUploadSize := ""
	if s.maxUploadSize > 0 {
		maxUploadSize = formatSize(s.maxUploadSize)
	}

	data := struct {
		Hostname     string
		WebAddress   string
		EmailContact string
		GAKey        string
		UserVoiceKey string

		MaxUploadSize string
	}{
		hostname,
		webAddress,
		s.emailContact,
		s.gaKey,
		s.userVoiceKey,

		maxUploadSize,
	}

	if acceptsHTML(r.Header) {
		if err := htmlTemplates.ExecuteTemplate(w, "index.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := textTemplates.ExecuteTemplate(w, "index.txt", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, http.StatusText(404), 404)
}

func sanitize(fileName string) string {
	return path.Base(fileName)
}

func (s *Server) postHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(_24K); nil != err {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred copying to output stream", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")

	responseBody := ""

	for _, fHeaders := range r.MultipartForm.File {
		for _, fHeader := range fHeaders {
			filename := sanitize(fHeader.Filename)

			var f io.Reader
			var err error

			if f, err = fHeader.Open(); err != nil {
				s.logger.Printf("%s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			file, err := ioutil.TempFile(s.tempPath, "transfer-")
			defer s.cleanTmpFile(file)

			if err != nil {
				s.logger.Printf("%s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			n, err := io.Copy(file, f)
			if err != nil {
				s.logger.Printf("%s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			contentLength := n

			_, err = file.Seek(0, io.SeekStart)
			if err != nil {
				s.logger.Printf("%s", err.Error())
				return
			}

			if s.maxUploadSize > 0 && contentLength > s.maxUploadSize {
				s.logger.Print("Entity too large")
				http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
				return
			}

			if s.performClamavPrescan {
				status, err := s.performScan(file.Name())
				if err != nil {
					s.logger.Printf("%s", err.Error())
					http.Error(w, "Could not perform prescan", http.StatusInternalServerError)
					return
				}

				if status != clamavScanStatusOK {
					s.logger.Printf("prescan positive: %s", status)
					http.Error(w, "Clamav prescan found a virus", http.StatusPreconditionFailed)
					return
				}
			}

			s.logger.Printf("Uploading %s %s %d %s", filename)

			if err = s.storage.Put(r.Context(), filename, file); err != nil {
				s.logger.Printf("Backend storage error: %s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return

			}

			filename = url.PathEscape(filename)
			relativeURL, _ := url.Parse(path.Join(s.proxyPath, filename))

			responseBody += fmt.Sprintln(getURL(r, s.proxyPort).ResolveReference(relativeURL).String())
		}
	}
	_, err := w.Write([]byte(responseBody))
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) cleanTmpFile(f *os.File) {
	if f != nil {
		err := f.Close()
		if err != nil {
			s.logger.Printf("Error closing tmpfile: %s (%s)", err, f.Name())
		}

		err = os.Remove(f.Name())
		if err != nil {
			s.logger.Printf("Error removing tmpfile: %s (%s)", err, f.Name())
		}
	}
}

func (s *Server) putHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	filename := sanitize(vars["filename"])

	contentLength := r.ContentLength

	defer storage.CloseCheck(r.Body.Close)

	file, err := ioutil.TempFile(s.tempPath, "transfer-")
	defer s.cleanTmpFile(file)
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// queue file to disk, because s3 needs content length
	// and clamav prescan scans a file
	n, err := io.Copy(file, r.Body)
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Cannot reset cache file", http.StatusInternalServerError)

		return
	}

	if contentLength < 1 {
		contentLength = n
	}

	if s.maxUploadSize > 0 && contentLength > s.maxUploadSize {
		s.logger.Print("Entity too large")
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}

	if contentLength == 0 {
		s.logger.Print("Empty content-length")
		http.Error(w, "Could not upload empty file", http.StatusBadRequest)
		return
	}

	if s.performClamavPrescan {
		status, err := s.performScan(file.Name())
		if err != nil {
			s.logger.Printf("%s", err.Error())
			http.Error(w, "Could not perform prescan", http.StatusInternalServerError)
			return
		}

		if status != clamavScanStatusOK {
			s.logger.Printf("prescan positive: %s", status)
			http.Error(w, "Clamav prescan found a virus", http.StatusPreconditionFailed)
			return
		}
	}

	s.logger.Printf("Uploading %s %s %d %s", filename)

	if err = s.storage.Put(r.Context(), filename, file); err != nil {
		s.logger.Printf("Error putting new file: %s", err.Error())
		http.Error(w, "Could not save file", http.StatusInternalServerError)
		return
	}

	// w.Statuscode = 200

	w.Header().Set("Content-Type", "text/plain")

	filename = url.PathEscape(filename)
	relativeURL, _ := url.Parse(path.Join(s.proxyPath, filename))

	_, _ = w.Write([]byte(resolveURL(r, relativeURL, s.proxyPort)))
}

func resolveURL(r *http.Request, u *url.URL, proxyPort string) string {
	r.URL.Path = ""

	return getURL(r, proxyPort).ResolveReference(u).String()
}

func resolveWebAddress(r *http.Request, proxyPath string, proxyPort string) string {
	rUrl := getURL(r, proxyPort)

	var webAddress string

	if len(proxyPath) == 0 {
		webAddress = fmt.Sprintf("%s://%s/",
			rUrl.ResolveReference(rUrl).Scheme,
			rUrl.ResolveReference(rUrl).Host)
	} else {
		webAddress = fmt.Sprintf("%s://%s/%s",
			rUrl.ResolveReference(rUrl).Scheme,
			rUrl.ResolveReference(rUrl).Host,
			proxyPath)
	}

	return webAddress
}

// Similar to the logic found here:
// https://github.com/golang/go/blob/release-branch.go1.14/src/net/http/clone.go#L22-L33
func cloneURL(u *url.URL) *url.URL {
	c := &url.URL{}
	*c = *u

	if u.User != nil {
		c.User = &url.Userinfo{}
		*c.User = *u.User
	}

	return c
}

func getURL(r *http.Request, proxyPort string) *url.URL {
	u := cloneURL(r.URL)

	if r.TLS != nil {
		u.Scheme = "https"
	} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		u.Scheme = proto
	} else {
		u.Scheme = "http"
	}

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = ""
	}

	p := idna.New(idna.ValidateForRegistration())
	var hostFromPunycode string
	hostFromPunycode, err = p.ToUnicode(host)
	if err == nil {
		host = hostFromPunycode
	}

	if len(proxyPort) != 0 {
		port = proxyPort
	}

	if len(port) == 0 {
		u.Host = host
	} else {
		if port == "80" && u.Scheme == "http" {
			u.Host = host
		} else if port == "443" && u.Scheme == "https" {
			u.Host = host
		} else {
			u.Host = net.JoinHostPort(host, port)
		}
	}

	return u
}

func (s *Server) lock(filename string) {
	key := path.Join(filename)

	lock, _ := s.locks.LoadOrStore(key, &sync.Mutex{})

	lock.(*sync.Mutex).Lock()
}

func (s *Server) unlock(filename string) {
	key := path.Join(filename)

	lock, _ := s.locks.LoadOrStore(key, &sync.Mutex{})

	lock.(*sync.Mutex).Unlock()
}

func (s *Server) headHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	filename := vars["filename"]

	contentLength, err := s.storage.Head(r.Context(), filename)
	if s.storage.IsNotExist(err) {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	} else if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not retrieve file.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Length", strconv.FormatUint(contentLength, 10))
	w.Header().Set("Connection", "close")

}

func (s *Server) getHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	filename := vars["filename"]

	reader, contentLength, err := s.storage.Get(r.Context(), filename)
	defer storage.CloseCheck(reader.Close)

	if s.storage.IsNotExist(err) {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	} else if err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Could not retrieve file.", http.StatusInternalServerError)
		return
	}

	var disposition string

	w.Header().Set("Content-Length", strconv.FormatUint(contentLength, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=\"%s\"", disposition, filename))
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-store")

	if _, err = io.Copy(w, reader); err != nil {
		s.logger.Printf("%s", err.Error())
		http.Error(w, "Error occurred copying to output stream", http.StatusInternalServerError)
		return
	}
}

// RedirectHandler handles redirect
func (s *Server) RedirectHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.forceHTTPS {
			// we don't want to enforce https
		} else if r.URL.Path == "/health.html" {
			// health check url won't redirect
		} else if strings.HasSuffix(ipAddrFromRemoteAddr(r.Host), ".onion") {
			// .onion addresses cannot get a valid certificate, so don't redirect
		} else if r.Header.Get("X-Forwarded-Proto") == "https" {
		} else if r.TLS != nil {
		} else {
			u := getURL(r, s.proxyPort)
			u.Scheme = "https"
			if len(s.proxyPort) == 0 && len(s.TLSListenerString) > 0 {
				_, port, err := net.SplitHostPort(s.TLSListenerString)
				if err != nil || port == "443" {
					port = ""
				}

				if len(port) > 0 {
					u.Host = net.JoinHostPort(u.Hostname(), port)
				} else {
					u.Host = u.Hostname()
				}
			}

			http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
			return
		}

		h.ServeHTTP(w, r)
	}
}

// LoveHandler Create a log handler for every request it receives.
func LoveHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-made-with", "<3 by DutchCoders")
		w.Header().Set("x-served-by", "Proudly served by DutchCoders")
		w.Header().Set("server", "Transfer.sh HTTP Server")
		h.ServeHTTP(w, r)
	}
}

func ipFilterHandler(h http.Handler, ipFilterOptions *IPFilterOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ipFilterOptions == nil {
			h.ServeHTTP(w, r)
		} else {
			WrapIPFilter(h, *ipFilterOptions).ServeHTTP(w, r)
		}
	}
}

func (s *Server) basicAuthHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AuthUser == "" || s.AuthPass == "" {
			h.ServeHTTP(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")

		username, password, authOK := r.BasicAuth()
		if !authOK {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if username != s.AuthUser || password != s.AuthPass {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	}
}
