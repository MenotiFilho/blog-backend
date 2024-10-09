package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var err error

// User model
type User struct {
	ID           uint   `json:"id" gorm:"primary_key"`
	Username     string `json:"username" gorm:"unique"`
	PasswordHash string `json:"password_hash"`
}

// Post model
type Post struct {
	ID      uint   `json:"id" gorm:"primary_key"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Tags    string `json:"tags"`
	Likes   int    `json:"likes"`
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

	// Public routes
	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")

	// Protected routes
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(jwtMiddleware)
	protected.HandleFunc("/posts", createPost).Methods("POST")
	protected.HandleFunc("/posts", getPosts).Methods("GET")

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
