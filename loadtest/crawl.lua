-- wrk crawler mix: package pages, listings, downloads, discovery of known releases
local uuidlist = {}
math.randomseed(os.time())
local f = io.open(os.getenv("UUIDS") or "uuids.txt")
for line in f:lines() do uuidlist[#uuidlist + 1] = line end
f:close()
request = function()
  local r = math.random()
  local i = math.random(0, 19999)
  local path
  if r < 0.45 then
    path = "/package/pkg" .. i .. "/1.0.0"
  elseif r < 0.60 then
    path = "/packages?page=" .. math.random(1, 400)
  elseif r < 0.68 then
    path = "/packages?format=CycloneDX&page=" .. math.random(1, 400)
  elseif r < 0.88 then
    path = "/artifact/" .. uuidlist[math.random(1, #uuidlist)] .. "/download"
  elseif r < 0.98 then
    path = "/discovery?tei=urn:tei:purl:localhost:pkg:pypi/pkg" .. math.random(0, 99999) .. "@1.0.0"
  else
    path = "/sitemap-" .. math.random(0, 2) .. ".xml"
  end
  return wrk.format("GET", path)
end
