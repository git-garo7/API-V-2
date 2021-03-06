import { Router } from 'express';

import usersRouter from '@modules/users/routes/users.routes';
import sessionsRouter from '@modules/users/routes/sessions.routes';
import productsRouter from '@modules/products/routes/products.routes';

const routes = Router();

routes.use('/products', productsRouter);
routes.use('/users', usersRouter);
routes.use('/sessions', sessionsRouter);

//routes.get('/', (req, res) => {
// return res.json({ message: 'hello dev/hello world' });
//});ERA PRA TESTE ESSA ROTA.

export default routes;
