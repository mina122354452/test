const express = require("express");
const maxmind = require("maxmind");
const requestIp = require("request-ip");

const app = express();
app.use(requestIp.mw());

app.get("/", async (req, res) => {
	const ip = req.clientIp;

	// Load the geoip database
	const lookup = await maxmind.open("./GeoLite2-City.mmdb"); // replace with your path to the database file

	// Perform the lookup
	let geo = lookup.get(ip);

	console.log(ip);
	console.log(geo);

	if (geo) {
		res.send(
			`Your IP is ${ip} and you are located in ${geo.city.names.en}, ${geo.subdivisions[0].iso_code}, ${geo.country.iso_code}`
		);
	} else {
		res.send(`Your IP is ${ip} but I couldn't find where you are located.`);
	}
});

app.listen(3000, () => console.log("Server started on port 3000"));
