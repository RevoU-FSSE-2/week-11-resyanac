const applyHelmet = require('./helmet');
const applyBodyParser = require('./bodyParser');
const applyMorgan = require('./morgan');
const applyCookieParser = require('./cookieparser');
const databaseMiddleware = require('./database-middleware');
const { checkRole } = require('./checkRole');


module.exports = (app) => {
  applyHelmet(app);
  applyBodyParser(app);
  applyMorgan(app);
  applyCookieParser(app);
  app.use(databaseMiddleware);
  app.use(checkRole)
}
