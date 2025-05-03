package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/kyrnas/chirpy/internal/auth"
	"github.com/kyrnas/chirpy/internal/database"
	_ "github.com/lib/pq"
	"golang.org/x/exp/slices"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	profanities    map[string]bool
	queries        *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type CreateChirpRequest struct {
	Body string `json:"body"`
}

type ChirpReponse struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

type UserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserReponse struct {
	Id           uuid.UUID `json:"id"`
	CreatedAt    string    `json:"created_at"`
	UpdatedAt    string    `json:"updated_at"`
	Email        string    `json:"email"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	Token string `json:"token"`
}

type PolkaEvent struct {
	Event string `json:"event"`
	Data  struct {
		UserId uuid.UUID `json:"user_id"`
	} `json:"data"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
}

func (cfg *apiConfig) middlewareJWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			rw.WriteHeader(401)
			json.NewEncoder(rw).Encode((ErrorResponse{Error: "Token not present"}))
			return
		}
		_, err = auth.ValidateJWT(token, cfg.jwtSecret)
		if err != nil {
			rw.WriteHeader(401)
			json.NewEncoder(rw).Encode((ErrorResponse{Error: "Failed to validate token"}))
			return
		}
		next.ServeHTTP(rw, req)
	})
}

func (cfg *apiConfig) middlewareKeyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		apiKey, err := auth.GetAPIKey(req.Header)
		if err != nil {
			rw.WriteHeader(401)
			json.NewEncoder(rw).Encode((ErrorResponse{Error: "API Key not present"}))
			return
		}
		if apiKey != cfg.polkaKey {
			rw.WriteHeader(401)
			json.NewEncoder(rw).Encode((ErrorResponse{Error: "API Key is invalid"}))
			return
		}
		next.ServeHTTP(rw, req)
	})
}

func (cfg *apiConfig) getChirpsHandler(rw http.ResponseWriter, req *http.Request) {
	authorId := req.URL.Query().Get("author_id")
	var chirps []database.Chirp
	var err error
	if authorId == "" {
		chirps, err = cfg.queries.GetAllChirps(req.Context())
	} else {
		authorUUID, err := uuid.Parse(authorId)
		if err != nil {
			rw.WriteHeader(400)
			json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid author ID"})
			return
		}
		chirps, err = cfg.queries.GetAllChirpsByAuthor(req.Context(), authorUUID)
	}
	if err != nil {
		rw.WriteHeader(500)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	sortOrder := req.URL.Query().Get("sort")
	if sortOrder == "desc" {
		slices.SortFunc(chirps, func(i, j database.Chirp) int {
			return j.CreatedAt.Time.Compare(i.CreatedAt.Time)
		})
	}
	var chirpResponse []ChirpReponse

	for _, chirp := range chirps {
		chirpResponse = append(chirpResponse, ChirpReponse{
			Id:        chirp.ID,
			CreatedAt: chirp.CreatedAt.Time.String(),
			UpdatedAt: chirp.UpdatedAt.Time.String(),
			Body:      chirp.Body,
			UserId:    chirp.UserID,
		})
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(200)
	json.NewEncoder(rw).Encode(chirpResponse)
}

func (cfg *apiConfig) getChirpHandler(rw http.ResponseWriter, req *http.Request) {
	chirpIDString := req.PathValue("chirpID")
	if chirpIDString == "" {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Chirp ID is required"})
		return
	}
	chirpID, err := uuid.Parse(chirpIDString)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid Chirp ID"})
		return
	}
	chirp, err := cfg.queries.GetChirp(req.Context(), chirpID)
	if err != nil {
		rw.WriteHeader(404)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Not found"})
		return
	}

	chirpResponse := ChirpReponse{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt.Time.String(),
		UpdatedAt: chirp.UpdatedAt.Time.String(),
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(200)
	json.NewEncoder(rw).Encode(chirpResponse)
}

func (cfg *apiConfig) deleteChirpHandler(rw http.ResponseWriter, req *http.Request) {
	chirpIDString := req.PathValue("chirpID")
	if chirpIDString == "" {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Chirp ID is required"})
		return
	}
	chirpID, err := uuid.Parse(chirpIDString)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid Chirp ID"})
		return
	}
	chirp, err := cfg.queries.GetChirp(req.Context(), chirpID)
	if err != nil {
		rw.WriteHeader(404)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Not found"})
		return
	}

	token, _ := auth.GetBearerToken(req.Header)
	userId, _ := auth.ValidateJWT(token, cfg.jwtSecret)

	if chirp.UserID != userId {
		rw.WriteHeader(403)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Forbidden"})
		return
	}

	err = cfg.queries.DeleteChirpById(req.Context(), chirpID)
	if err != nil {
		rw.WriteHeader(500)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Internal server errror"})
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(204)
}

func (cfg *apiConfig) createChirpHandler(rw http.ResponseWriter, req *http.Request) {
	var chirpRequest CreateChirpRequest
	err := json.NewDecoder(req.Body).Decode(&chirpRequest)
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid chirp"})
		return
	}
	if len(chirpRequest.Body) > 140 {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Chirp is too long"})
		return
	}
	words := strings.Fields(chirpRequest.Body)
	for i, word := range words {
		if cfg.profanities[strings.ToLower(word)] {
			words[i] = "****"
		}
	}

	token, _ := auth.GetBearerToken(req.Header)
	userId, _ := auth.ValidateJWT(token, cfg.jwtSecret)

	dbChirp, err := cfg.queries.CreateChirp(req.Context(), database.CreateChirpParams{
		UserID: userId,
		Body:   strings.Join(words, " "),
	})
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid chirp"})
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(201)

	chirpResponse := ChirpReponse{
		Id:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt.Time.String(),
		UpdatedAt: dbChirp.UpdatedAt.Time.String(),
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	}
	json.NewEncoder(rw).Encode(chirpResponse)
}

func (cfg *apiConfig) metricsHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(200)
	rw.Write([]byte(fmt.Sprintf(
		`
			<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
			</html>
		`,
		int(cfg.fileserverHits.Load()),
	)))
}

func (cfg *apiConfig) resetHandler(rw http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		rw.WriteHeader(403)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Forbidden"})
		return
	}
	cfg.fileserverHits.Store(0)
	cfg.queries.DeleteAllUsers(req.Context())
	rw.WriteHeader(200)
}

func (cfg *apiConfig) createUserHandler(rw http.ResponseWriter, req *http.Request) {
	var requestBody UserRequest
	err := json.NewDecoder(req.Body).Decode(&requestBody)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid request"})
		return
	}
	hashedPassword, err := auth.HashPassword(requestBody.Password)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Issue hashing password"})
		return
	}
	dbUser, err := cfg.queries.CreateUser(req.Context(), database.CreateUserParams{
		Email:          requestBody.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid request"})
		return
	}
	user := UserReponse{
		Id:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt.Time.String(),
		UpdatedAt:   dbUser.UpdatedAt.Time.String(),
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed.Bool,
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(201)
	json.NewEncoder(rw).Encode(user)
}

func (cfg *apiConfig) loginUserHandler(rw http.ResponseWriter, req *http.Request) {
	var requestBody UserRequest
	err := json.NewDecoder(req.Body).Decode(&requestBody)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid request"})
		return
	}
	hashedPassword, err := cfg.queries.GetUserHashedPasswordByEmail(req.Context(), requestBody.Email)
	if err != nil {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "User not found"})
		return
	}
	err = auth.CheckPasswordHash(hashedPassword, requestBody.Password)
	if err != nil {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid password"})
		return
	}
	tokenExpiration := time.Hour

	dbUser, _ := cfg.queries.GetUserByEmail(req.Context(), requestBody.Email)
	token, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, tokenExpiration)
	if err != nil {
		rw.WriteHeader(500)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Unable to create JWT token"})
		return
	}

	refreshToken, _ := auth.MakeRefreshToken()

	cfg.queries.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})

	user := UserReponse{
		Id:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt.Time.String(),
		UpdatedAt:    dbUser.UpdatedAt.Time.String(),
		Email:        dbUser.Email,
		IsChirpyRed:  dbUser.IsChirpyRed.Bool,
		Token:        token,
		RefreshToken: refreshToken,
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(200)
	json.NewEncoder(rw).Encode(user)
}

func (cfg *apiConfig) updateUserHandler(rw http.ResponseWriter, req *http.Request) {
	var requestBody UserRequest
	err := json.NewDecoder(req.Body).Decode(&requestBody)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Invalid request"})
		return
	}
	token, _ := auth.GetBearerToken(req.Header)
	userId, _ := auth.ValidateJWT(token, cfg.jwtSecret)
	newHashedPassword, err := auth.HashPassword(requestBody.Password)
	if err != nil {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Unable to hash password"})
		return
	}
	userEntity, err := cfg.queries.UpdateUserEmailAndPassoword(req.Context(), database.UpdateUserEmailAndPassowordParams{Email: requestBody.Email, HashedPassword: newHashedPassword, ID: userId})
	if err != nil {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Unable to update user"})
		return
	}
	tokenExpiration := time.Hour

	newToken, err := auth.MakeJWT(userId, cfg.jwtSecret, tokenExpiration)
	if err != nil {
		rw.WriteHeader(500)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Unable to create JWT token"})
		return
	}

	refreshToken, _ := auth.MakeRefreshToken()

	cfg.queries.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    userId,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})

	user := UserReponse{
		Id:           userId,
		CreatedAt:    userEntity.CreatedAt.Time.String(),
		UpdatedAt:    userEntity.UpdatedAt.Time.String(),
		Email:        userEntity.Email,
		IsChirpyRed:  userEntity.IsChirpyRed.Bool,
		Token:        newToken,
		RefreshToken: refreshToken,
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(200)
	json.NewEncoder(rw).Encode(user)
}

func (cfg *apiConfig) upgradeChirpyRedHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	var polkaEvent PolkaEvent
	err := json.NewDecoder(req.Body).Decode(&polkaEvent)
	if err != nil {
		rw.WriteHeader(400)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Unable to decode body"})
		return
	}
	if polkaEvent.Event != "user.upgraded" {
		rw.WriteHeader(204)
		return
	}
	_, err = cfg.queries.UpgradeChirpyRedById(req.Context(), database.UpgradeChirpyRedByIdParams{IsChirpyRed: sql.NullBool{Bool: true, Valid: true}, ID: polkaEvent.Data.UserId})
	if err != nil {
		rw.WriteHeader(404)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "User not found"})
		return
	}
	rw.WriteHeader(204)
}

func (cfg *apiConfig) refreshTokenHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Token not present"})
		return
	}

	refreshEntity, err := cfg.queries.GetRefreshToken(req.Context(), refreshToken)
	if err != nil || refreshEntity.RevokedAt.Valid || refreshEntity.ExpiresAt.Before(time.Now()) {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Token is invalid"})
		return
	}

	newToken, err := auth.MakeJWT(refreshEntity.UserID, cfg.jwtSecret, time.Hour)
	if err != nil {
		rw.WriteHeader(500)
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Failed to create a new token"})
		return
	}

	refreshResponse := RefreshTokenResponse{Token: newToken}
	rw.WriteHeader(200)
	json.NewEncoder(rw).Encode(refreshResponse)
}

func (cfg *apiConfig) revokeTokenHandler(rw http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		rw.WriteHeader(401)
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(ErrorResponse{Error: "Token not present"})
		return
	}

	cfg.queries.ExpireRefreshToken(req.Context(), refreshToken)
	rw.WriteHeader(204)
}

func healthHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(200)
	rw.Write([]byte("OK"))
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}

	dbQueries := database.New(db)

	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	apiCfg := &apiConfig{fileserverHits: atomic.Int32{}, profanities: map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}, queries: dbQueries, platform: platform, jwtSecret: jwtSecret, polkaKey: polkaKey}

	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.Handle("POST /api/chirps", apiCfg.middlewareJWTAuth(http.HandlerFunc(apiCfg.createChirpHandler)))
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.Handle("DELETE /api/chirps/{chirpID}", apiCfg.middlewareJWTAuth(http.HandlerFunc(apiCfg.deleteChirpHandler)))
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginUserHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshTokenHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeTokenHandler)
	mux.Handle("PUT /api/users", apiCfg.middlewareJWTAuth(http.HandlerFunc(apiCfg.updateUserHandler)))
	mux.Handle("POST /api/polka/webhooks", apiCfg.middlewareKeyAuth(http.HandlerFunc(apiCfg.upgradeChirpyRedHandler)))
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	server.ListenAndServe()
}
