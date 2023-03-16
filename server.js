const app = require('./.data/app.js');
require('dotenv').config();

const port = 3000;

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});