package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
)

var db *gorm.DB
var err error

// User model
type User struct {
	ID           uint   `json:"id" gorm:"primary_key"`
	Username     string `json:"username" gorm:"unique"`
	PasswordHash string `json:"password_hash"`
	ProfilePic   string `json:"profile_pic"`
}

// Post model
type Post struct {
	ID      uint     `json:"id" gorm:"primary_key"`
	Title   string   `json:"title"`
	Content string   `json:"content"`
	Tags    string   `json:"tags"`
	Likes   int      `json:"likes"`
	Images  []string `json:"images" gorm:"type:jsonb"`
}

var jwtKey = []byte("my_secret_key") // Secret key for signing JWTs

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {

	// Connect to the database
	connStr := os.Getenv("DATABASE_URL")
	for i := 0; i < 30; i++ {
		db, err = gorm.Open("postgres", connStr)
		if err == nil {
			break
		}
		log.Printf("Failed to connect to database (attempt %d/30): %v", i+1, err)
		time.Sleep(10 * time.Second)
	}

	if err != nil {
		log.Fatalf("Failed to connect to database after 30 attempts: %v", err)
	}
	defer db.Close()
	fmt.Println("Successfully connected to the database")

	db.AutoMigrate(&User{}, &Post{}) // AutoMigrate the User and Post models

	r := mux.NewRouter()

	// Serve the root HTML page
	r.HandleFunc("/", rootHandler).Methods("GET")

	// Public routes
	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/posts", getPosts).Methods("GET")

	// Protected routes
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(jwtMiddleware)
	protected.HandleFunc("/posts", createPost).Methods("POST")

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// Signup handler (user creation)
func signup(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if the username is already taken
	var existingUser User
	if err := db.Where("username = ?", creds.Username).First(&existingUser).Error; err == nil {
		http.Error(w, "Username already taken", http.StatusBadRequest)
		return
	}

	// Hash the password before saving it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}

	// Create the user
	user := User{
		Username:     creds.Username,
		PasswordHash: string(hashedPassword),
	}

	// Save the user to the database
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User created successfully",
	})
}

// Login handler (user authentication)
func login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Find the user in the database
	var user User
	if err := db.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare the stored hashed password with the one provided
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// If the credentials are correct, create a new token
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"token":   tokenString,
	})
}

// JWT Middleware to protect certain routes
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " from the token string
		tokenStr = tokenStr[len("Bearer "):]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Create Post handler
func createPost(w http.ResponseWriter, r *http.Request) {
	var post Post
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := db.Create(&post).Error; err != nil {
		http.Error(w, "Could not create post", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(post)
}

// Get Posts handler
func getPosts(w http.ResponseWriter, r *http.Request) {
	var posts []Post
	if err := db.Find(&posts).Error; err != nil {
		http.Error(w, "Could not retrieve posts", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(posts)
}

// UploadImageToCloudinary uploads an image to Cloudinary and returns the URL
func UploadImageToCloudinary(file multipart.File, fileHeader *multipart.FileHeader) (string, error) {
	// Inicialize o Cloudinary com suas credenciais
	cld, err := cloudinary.NewFromParams(os.Getenv("CLOUDINARY_CLOUD_NAME"), os.Getenv("CLOUDINARY_API_KEY"), os.Getenv("CLOUDINARY_API_SECRET"))
	if err != nil {
		return "", fmt.Errorf("falha ao inicializar Cloudinary: %v", err)
	}

	ctx := context.Background()

	// Faça o upload do arquivo para o Cloudinary
	uploadResult, err := cld.Upload.Upload(ctx, file, uploader.UploadParams{
		Folder: "blog_images", // Cria uma pasta chamada "blog_images" para organizar suas imagens
	})
	if err != nil {
		return "", fmt.Errorf("falha ao fazer upload: %v", err)
	}

	// Retorna a URL pública da imagem
	return uploadResult.SecureURL, nil
}

// Handle image upload from user
func uploadImageHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form containing the image
	err := r.ParseMultipartForm(10 << 20) // Limite de 10MB
	if err != nil {
		http.Error(w, "Falha ao processar a imagem", http.StatusBadRequest)
		return
	}

	// Obtenha o arquivo enviado
	file, fileHeader, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Não foi possível obter o arquivo", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Faça o upload da imagem para o Cloudinary
	imageURL, err := UploadImageToCloudinary(file, fileHeader)
	if err != nil {
		http.Error(w, fmt.Sprintf("Falha ao fazer upload: %v", err), http.StatusInternalServerError)
		return
	}

	// Retorne a URL da imagem para o cliente
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"url": imageURL,
	})
}

// Root handler to serve a simple HTML page
func rootHandler(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Server Status</title>
	</head>
	<body>
		<h1>The server is up and running!</h1>
		<p>Visit the <a href="/posts">/posts</a> endpoint to see all posts.</p>
	</body>
	</html>
	`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
