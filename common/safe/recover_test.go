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
	done := make(chan bool)
	
	// Start a goroutine that will panic
	Go("test", func() {
		defer func() {
			// This defer should not be reached because safe.Go handles the panic
			done <- false
		}()
		panic("test panic")
	})

	// Give it time to panic and recover
	time.Sleep(100 * time.Millisecond)
	
	// The goroutine should have recovered, not crashed the process
	// We can't easily verify the metric was incremented without mocking,
	// but we can verify the process didn't crash
	select {
	case <-done:
		t.Fatal("defer after panic should not have been reached")
	default:
		// Success - goroutine panicked and was recovered
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
