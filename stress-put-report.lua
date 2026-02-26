-- wrk script for PUT stress test with response tracking

counter = 0
responses = {}

request = function()
    counter = counter + 1
    local key = "/stress-rpt-" .. counter
    local body = "value-" .. counter .. "-" .. string.rep("x", 128)
    return wrk.format("PUT", key, nil, body)
end

response = function(status, headers, body)
    if responses[status] == nil then
        responses[status] = 0
    end
    responses[status] = responses[status] + 1
end

done = function(summary, latency, requests)
    io.write("\n--- Response Status Breakdown ---\n")
    for status, count in pairs(responses) do
        io.write(string.format("  HTTP %d: %d responses\n", status, count))
    end
    io.write(string.format("\n  Total errors (connect/read/write/timeout): %d/%d/%d/%d\n",
        summary.errors.connect, summary.errors.read, summary.errors.write, summary.errors.timeout))
end
