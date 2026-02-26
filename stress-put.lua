-- wrk script for PUT stress test
-- Each request PUTs a unique key with a small payload

counter = 0

request = function()
    counter = counter + 1
    local key = "/stress-key-" .. counter
    local body = "value-" .. counter .. "-" .. string.rep("x", 128)
    return wrk.format("PUT", key, nil, body)
end
