package webcontroller

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/its-a-feature/Mythic/authentication"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
)

func TestProviderCallbackExportContainsDescriptorWithoutSessionHandle(t *testing.T) {
	config := ExportCallbackConfiguration{CryptoProviderManaged: true}
	config.Callback.CryptoProviderBindingID = sql.NullString{String: "private-session-binding", Valid: true}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"crypto_provider_managed":true`) || strings.Contains(string(encoded), "private-session-binding") {
		t.Fatalf("export did not preserve the safe provider descriptor: %s", encoded)
	}
}

func TestProviderCallbackConfigCannotImportAsPortableKeys(t *testing.T) {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"input":{"config":{"crypto_provider_managed":true}}}`))
	context.Request.Header.Set("Content-Type", "application/json")
	context.Set(authentication.ContextKeyOperatorOperationStruct, &databaseStructs.Operatoroperation{})
	// The handler must reject before querying or creating any application rows.
	ImportCallbackConfigWebhook(context)
	var result ImportCallbackConfigResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "error" || !strings.Contains(result.Error, "new authenticated session") {
		t.Fatalf("provider callback import was not rejected: %+v", result)
	}
}
