package ladle

import (
	"encoding/json"
	"net/http"
)

func (i Issuer) ChiJwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		token := r.Header.Get("token")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			output := map[string]string{"message": "no authentication data found"}
			json.NewEncoder(w).Encode(output)
			return
		}

		ctx, err := i.ValidateJWT(r.Context(), token)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			output := map[string]string{
				"message": "JWT validation failed",
				"error":   err.Error(),
			}
			json.NewEncoder(w).Encode(output)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
