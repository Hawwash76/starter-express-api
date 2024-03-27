const cors = require("cors");
const express = require("express");
const dns = require("dns");
const bodyParser = require("body-parser");

const app = express();
const port = 3001;
app.use(cors());

app.use(bodyParser.json());

app.post("/checkDomain", async (req, res) => {
  const { message } = req.body;
  try {
    const [MXChanges, SPFRecords, DMARCRecords, DKIMRecords, Blacklist] =
      await Promise.all([
        checkMXChanges(message).catch((err) => {
          console.error(`Error checking MX changes: ${err.message}`);
          return null; // or return an empty object if preferred
        }),
        checkSPFRecord(message).catch((err) => {
          console.error(`Error checking SPF records: ${err.message}`);
          return null;
        }),
        checkDMARCRecord(message).catch((err) => {
          console.error(`Error checking DMARC records: ${err.message}`);
          return null;
        }),
        checkDKIMRecords(message).catch((err) => {
          console.error(`Error checking DKIM records: ${err.message}`);
          return null;
        }),
        checkBlacklist(message).catch((err) => {
          console.error(`Error checking Blacklist: ${err.message}`);
          return null; // or return an empty object if preferred
        }),
      ]);

    const results = {
      MXChanges,
      SPFRecords,
      DMARCRecords,
      DKIMRecords,
      Blacklist,
    };
    res.status(200).send(results);
  } catch (error) {
    console.log(error);
    res.status(300).send(error);
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

function checkMXChanges(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err) {
        reject(err);
      } else {
        resolve(addresses);
      }
    });
  });
}

function checkSPFRecord(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(`_spf.${domain}`, (err, records) => {
      if (err) {
        reject(err);
      } else {
        resolve(records);
      }
    });
  });
}

function checkDMARCRecord(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(`_dmarc.${domain}`, (err, records) => {
      if (err) {
        reject(err);
      } else {
        resolve(records);
      }
    });
  });
}

function checkDKIMRecords(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(`_domainkey.${domain}`, (err, records) => {
      if (err) {
        reject(err);
      } else {
        resolve(records);
      }
    });
  });
}

async function checkBlacklist(domain) {
  try {
    const username = "key_4Q2wFaxHptVj8mOn63EEsexne";
    const password = ""; // Leave empty for password-less auth
    const basicAuth =
      "Basic " + Buffer.from(username + ":" + password).toString("base64");

    const response = await fetch(
      "https://api.blacklistchecker.com/check/" + domain,
      {
        method: "GET",
        headers: {
          Authorization: basicAuth,
        },
      }
    );

    const data = await response.json();

    return data.blacklists;
  } catch (error) {
    console.error("Error making request:", error);
  }
}
