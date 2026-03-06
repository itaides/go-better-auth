package handlers

import (
	"net/http"

	"github.com/GoBetterAuth/go-better-auth/v2/internal/util"
	"github.com/GoBetterAuth/go-better-auth/v2/models"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/two-factor/types"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/two-factor/usecases"
)

type EnableHandler struct {
	UseCase usecases.EnableUseCase
}

func (h *EnableHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqCtx, _ := models.GetRequestContext(ctx)

		if reqCtx.UserID == nil || *reqCtx.UserID == "" {
			reqCtx.SetJSONResponse(http.StatusUnauthorized, map[string]any{
				"message": "authentication required",
			})
			reqCtx.Handled = true
			return
		}

		var payload types.EnableRequest
		if err := util.ParseJSON(r, &payload); err != nil {
			reqCtx.SetJSONResponse(http.StatusUnprocessableEntity, map[string]any{
				"message": "invalid request body",
			})
			reqCtx.Handled = true
			return
		}

		result, err := h.UseCase.Enable(ctx, *reqCtx.UserID, payload.Password, payload.Issuer)
		if err != nil {
			reqCtx.SetJSONResponse(http.StatusBadRequest, map[string]any{
				"message": err.Error(),
			})
			reqCtx.Handled = true
			return
		}

		reqCtx.SetJSONResponse(http.StatusOK, &types.EnableResponse{
			TotpURI:     result.TotpURI,
			BackupCodes: result.BackupCodes,
		})
	}
}
