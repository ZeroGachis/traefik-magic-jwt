// TODO: Tests are disabled for now as they depends on bou.ke/monkey which is archived and has a restrictive license
package traefik_magic_jwt_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bou.ke/monkey"
	traefik_magic_jwt "github.com/ZeroGachis/traefik-magic-jwt"
)

func TestServiceOk(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 26, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MTk0NjE5MzksInVzZXJfaWQiOjEsImV4cCI6MTYxOTQ2NTUzOX0.DPWzZSEVpIlvPhWNqYxZEaeR3tN9t8heeV7YXHOOze9ECYD9uNYGn3o5QBqyMXQslVgnM62pNkHcWi2yriNe8M8Yjmk3mWhGKF6L5llxOL3jHN7Euyh7t1bnCqyetsaPoDEtiR50C0qQyV9Dm0eyrC-ZfDKWWU24Ak816AP--QOyyrDD2eBFyDYH9u1vjn94-UtPiFXL_Weu_sVcCMK47YT5mOZklGQMtHr-7x2q6nS1lKAQT27nBam78Hl8kd0RVaA5lyDxrRsSpvxemisVKljByxwWNrnrvRHNnJoJ6b1QXbdiUdzK3uUpQJkzcehrre0QVrraPJSjVw2iP9iQHg"}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was called")
	}
	if recorder.Code != 200 {
		t.Fatal("response expect 200")
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `` {
		t.Fatal("Bad Body")
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `{"iat":1619461939,"user_id":1,"exp":1619465539}` {
		t.Fatalf("Header Is `%s`", h)
	}
}

func TestServiceOkHS(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 26, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	cfg.Alg = "HS256"
	cfg.Key = "6990ff1osITn6JaLC5EU9QI1AEMaghDTgzvpqNid"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MjQ0NDk1NDMsInVzZXJfaWQiOjEsImV4cCI6MTYyNDQ1MzE0M30.ICUuzJ9a8aq4SD1MFm3qJ1M-da3vszXAydwsYvAxbM0"}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was called")
	}
	if recorder.Code != 200 {
		t.Fatal("response expect 200")
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `` {
		t.Fatal("Bad Body")
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `{"iat":1624449543,"user_id":1,"exp":1624453143}` {
		t.Fatalf("Header Is `%s`", h)
	}
}
func TestServiceBadToken(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 26, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MTk0NjE5MzksInVzZXJfaWQiOjEsImV4cCI6MTYxOTQ2NTUzOX0.DPWzZSEVpIlvPhWNqYxZEaeR3tN9t8heeV7YXHOOze9ECYD9uNYGn3o5QBqyMXQslVgnM62pNkHcWi2yriNe8M8Yjmk3mWhGKF6L5llxOL3jHN7Euyh7t1bnCqyetsaPoDEtiR50C0qQyV9Dm0eyrC-ZfDKWWU24Ak816AP--QOyyrDD2eBFyDYH9u1vjn94-UtPiFXL_Weu_sVcCMK47YT5mOZklGQMtHr-7x2q6nS1lKAQT27nBam78Hl8kd0RVaA5lyDxrRsSpzK3uUpQJkzcehrre0QVrraPJSjVw2iP9iQHg"}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("response expect 400 = %d", recorder.Code)
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `Invalid Token` {
		t.Fatalf("Bad Body `%s`", string(body))
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `` {
		t.Fatalf("Header Is `%s`", h)
	}
}

func TestServiceNoToken(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 26, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatal("response expect 401")
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `No Token Detect` {
		t.Fatalf("Bad Body `%s`", string(body))
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `` {
		t.Fatalf("Header Is `%s`", h)
	}
}

func TestServiceIgnoreUrl(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 26, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	cfg.White = map[string]*traefik_magic_jwt.WhiteUrl{
		"login": {
			URL:    "/login",
			Method: http.MethodPost,
		},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if recorder.Code != http.StatusOK {
		t.Fatal("response expect 200")
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `` {
		t.Fatalf("Bad Body `%s`", string(body))
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `` {
		t.Fatalf("Header Is `%s`", h)
	}
}

func TestServiceExpired(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 28, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MTk0NjE5MzksInVzZXJfaWQiOjEsImV4cCI6MTYxOTQ2NTUzOX0.DPWzZSEVpIlvPhWNqYxZEaeR3tN9t8heeV7YXHOOze9ECYD9uNYGn3o5QBqyMXQslVgnM62pNkHcWi2yriNe8M8Yjmk3mWhGKF6L5llxOL3jHN7Euyh7t1bnCqyetsaPoDEtiR50C0qQyV9Dm0eyrC-ZfDKWWU24Ak816AP--QOyyrDD2eBFyDYH9u1vjn94-UtPiFXL_Weu_sVcCMK47YT5mOZklGQMtHr-7x2q6nS1lKAQT27nBam78Hl8kd0RVaA5lyDxrRsSpvxemisVKljByxwWNrnrvRHNnJoJ6b1QXbdiUdzK3uUpQJkzcehrre0QVrraPJSjVw2iP9iQHg"}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
	if recorder.Code != 451 {
		t.Fatalf("response expect 451 = %d", recorder.Code)
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `Expired Token` {
		t.Fatalf("Bad Body `%s`", string(body))
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `` {
		t.Fatalf("Header Is `%s`", h)
	}
}

func TestServiceExpiredIgnore(t *testing.T) {
	monkey.Patch(time.Now, func() time.Time {
		return time.Date(2021, 04, 28, 18, 40, 58, 651387237, time.UTC)
	})
	cfg := traefik_magic_jwt.CreateConfig()
	cfg.White = map[string]*traefik_magic_jwt.WhiteUrl{
		"login": {
			URL:    "/login",
			Method: http.MethodPut,
			Type:   "refresh",
		},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	jwt, err := traefik_magic_jwt.New(ctx, next, cfg, "test-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MTk0NjE5MzksInVzZXJfaWQiOjEsImV4cCI6MTYxOTQ2NTUzOX0.DPWzZSEVpIlvPhWNqYxZEaeR3tN9t8heeV7YXHOOze9ECYD9uNYGn3o5QBqyMXQslVgnM62pNkHcWi2yriNe8M8Yjmk3mWhGKF6L5llxOL3jHN7Euyh7t1bnCqyetsaPoDEtiR50C0qQyV9Dm0eyrC-ZfDKWWU24Ak816AP--QOyyrDD2eBFyDYH9u1vjn94-UtPiFXL_Weu_sVcCMK47YT5mOZklGQMtHr-7x2q6nS1lKAQT27nBam78Hl8kd0RVaA5lyDxrRsSpvxemisVKljByxwWNrnrvRHNnJoJ6b1QXbdiUdzK3uUpQJkzcehrre0QVrraPJSjVw2iP9iQHg"}
	jwt.ServeHTTP(recorder, req)
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if recorder.Code != 200 {
		t.Fatalf("response expect 200 = %d", recorder.Code)
	}
	resp := recorder.Result()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `` {
		t.Fatalf("Bad Body `%s`", string(body))
	}
	h := req.Header.Get(cfg.InjectHeader)
	if h != `{"iat":1619461939,"user_id":1,"exp":1619465539}` {
		t.Fatalf("Header Is `%s`", h)
	}
}
