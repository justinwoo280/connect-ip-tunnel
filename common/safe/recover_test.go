package safe

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGo_NoPanic(t *testing.T) {
	done := make(chan bool)
	Go("test", func() {
		done <- true
	})

	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Fatal("goroutine did not complete")
	}
}

func TestGo_WithPanic(t *testing.T) {
	// 验证 safe.Go 包裹的 goroutine 即使 panic 也不会导致进程崩溃。
	//
	// 注意：fn 内部的 defer 仍然会执行（这是 Go 语言规范）；safe.Go 的 recover
	// 只是阻止 panic 继续向上冒泡导致进程退出。下面的设计：
	//   - inner defer 会被触发并向 inside 信号 channel 写入 true（说明 fn 真的进入了 panic 路径）
	//   - safe.Go 的外层 defer 接住 panic 后 goroutine 正常退出
	//   - 主 goroutine 此时仍然存活 → 测试通过
	inside := make(chan bool, 1)

	Go("test", func() {
		defer func() {
			// fn 内 defer 必然执行 —— 这是 Go 语言规范保证的。
			// 通过这个信号确认 panic 路径走到了。
			inside <- true
		}()
		panic("test panic")
	})

	select {
	case <-inside:
		// 正确：fn 内 defer 跑了，panic 也被外层 safe.Go 接住（进程没崩）
	case <-time.After(time.Second):
		t.Fatal("inner defer did not execute within timeout (panic path not entered)")
	}

	// 第二次 sanity check：再起一个不 panic 的 safe.Go，验证整个进程仍然能正常调度
	done := make(chan struct{})
	Go("test", func() {
		close(done)
	})
	select {
	case <-done:
		// 进程仍然存活并能正常起新 goroutine
	case <-time.After(time.Second):
		t.Fatal("process appears to be in a bad state after recovered panic")
	}
}

func TestHTTP_NoPanic(t *testing.T) {
	handler := HTTP("test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if w.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", w.Body.String())
	}
}

func TestHTTP_WithPanic(t *testing.T) {
	handler := HTTP("test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// This should not crash the test
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
	
	body := w.Body.String()
	if body != "internal error\n" {
		t.Errorf("expected body 'internal error\\n', got %q", body)
	}
}
