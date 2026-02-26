-- wrk script for mixed workload stress test
-- Mix of PUT, GET, and DELETE operations

counter = 0

request = function()
    counter = counter + 1
    local op = counter % 10
    local key = "/mixed-key-" .. (counter % 200 + 1)

    if op < 5 then
        -- 50% PUTs
        local body = "val-" .. counter .. "-" .. string.rep("y", 64)
        return wrk.format("PUT", key, nil, body)
    elseif op < 9 then
        -- 40% GETs
        return wrk.format("GET", key, nil, nil)
    else
        -- 10% DELETEs
        return wrk.format("DELETE", key, nil, nil)
    end
end
