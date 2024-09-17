package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var jwtSecret = []byte("Anubhav")

// Struct for login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Mocked users for example purposes
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Function to generate a JWT token for a user
func generateToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
	})
	return token.SignedString(jwtSecret)
}

// Middleware to authenticate JWT from the cookie
func authenticateToken(c *gin.Context) {
	cookie, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		c.Set("username", claims["username"])
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

// Login handler for authentication
func loginHandler(c *gin.Context) {
	println("helo")
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Verify the credentials
	if password, ok := users[req.Username]; !ok || password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}

	// Generate JWT token if valid credentials
	token, err := generateToken(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not generate token"})
		return
	}

	// Set JWT token as a cookie
	c.SetCookie("token", token, 3600, "/", "localhost", false, true)

	// Send success response with the token in the body as well
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

// Protected route example
func protectedHandler(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{"message": "Hello, " + username.(string)})
}

// Logout handler to clear the token cookie
func logoutHandler(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func main() {
	// Create a new Gin router
	r := gin.Default()

	// r.Use(cors.New(cors.Config{
	// 	AllowOrigins:     []string{"http://localhost:5173"}, // Replace with your frontend URL
	// 	AllowMethods:     []string{"POST", "GET", "PUT", "DELETE", "OPTIONS"},
	// 	AllowHeaders:     []string{"Content-Type", "Authorization"},
	// 	AllowCredentials: true, // Required for cookies or tokens in requests
	// }))
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Allow all origins
		AllowMethods:     []string{"POST", "GET", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"}, // Add more headers as needed
		AllowCredentials: true,                                      // Allow credentials like cookies
	}))

	// Login route
	r.POST("/api/login", loginHandler)

	// Protected route
	r.GET("/api/protected", authenticateToken, protectedHandler)

	// Logout route
	r.POST("/api/logout", logoutHandler)

	// Handle 404 errors
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "404 Not Found"})
	})

	// Start the server on port 8080
	r.Run(":8080")
}
