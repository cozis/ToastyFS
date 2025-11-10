#ifndef CONFIG_INCLUDED
#define CONFIG_INCLUDED

#define MAX_SERVER_ADDRS 4
#define MAX_CHUNK_SERVERS 128
#define MAX_OPERATIONS 128
#define MAX_REQUESTS_PER_QUEUE 128

#define REPLICATION_FACTOR 3

// Health check configuration (in milliseconds)
#define HEALTH_CHECK_INTERVAL 30000   // Send STATE_UPDATE every 30 seconds
#define HEALTH_CHECK_TIMEOUT  90000   // Mark as unhealthy after 90 seconds without response

#endif // CONFIG_INCLUDED
