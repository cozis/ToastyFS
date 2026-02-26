-- wrk script for GET stress test
-- Reads previously written keys

counter = 0

request = function()
    counter = counter + 1
    local key = "/stress-key-" .. (counter % 100 + 1)
    return wrk.format("GET", key, nil, nil)
end
