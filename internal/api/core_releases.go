package api

import (
	"context"
	"net/http"
	"time"
	"xrayrelay/internal/coreversion"
)

var officialCoreCatalog = coreversion.NewCatalog()

func serveCoreReleases(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	force := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "1"
	result, err := officialCoreCatalog.List(ctx, force)
	status := http.StatusOK
	if err != nil {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, result)
}
