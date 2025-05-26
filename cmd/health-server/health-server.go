package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthResponse represents the health check API response
type HealthResponse struct {
	Timestamp int64 `json:"timestamp"`
}

var (
	// Global variables for configuration
	serverStartTime int64
	customTimestamp int64
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 2025, "Port to listen on")
	timestamp := flag.Int64("timestamp", 0, "Custom timestamp (0 means use server start time)")
	flag.Parse()

	// Set timestamps
	serverStartTime = time.Now().Unix()
	if *timestamp != 0 {
		customTimestamp = *timestamp
	} else {
		customTimestamp = serverStartTime
	}

	// Create Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Health check endpoint
	r.GET("/get-dns-time", getHealthTime)

	// Start server
	addr := ":" + strconv.Itoa(*port)
	fmt.Printf("Health check server starting on port %d\n", *port)
	fmt.Printf("Using timestamp: %d\n", customTimestamp)
	
	log.Fatal(http.ListenAndServe(addr, r))
}

// getHealthTime handles the health check endpoint
func getHealthTime(c *gin.Context) {
	response := HealthResponse{
		Timestamp: customTimestamp,
	}
	c.JSON(http.StatusOK, response)
}