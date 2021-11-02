import type { Express } from 'express';
import { customAlphabet } from 'nanoid';
import { getEnv } from '../../env.js';
import { auth } from '../auth/middleware.js';
import { Db } from '../db/db.js';

export default (app: Express) => {
  const db = Db.getDb();

  async function latestView(username: string): Promise<any> {
    const { rows } = await db.query(`
      SELECT view
      FROM ui.view
      WHERE view->'meta'->>'owner' = '${username}'
      OR view->'meta'->>'owner' = 'system'
      ORDER BY view->'meta'->>'timeUpdated' DESC;
    `);

    const userViews = [];
    const systemViews = [];
    for (const row of rows) {
      const { view } = row;
      const { owner } = view.meta;
      if (owner === username) {
        userViews.push(view);
      }
      if (owner === 'system') {
        systemViews.push(view);
      }
    }

    if (userViews.length) {
      const [userView] = userViews;
      return userView;
    } else if (systemViews.length) {
      const [systemView] = systemViews;
      return systemView;
    } else {
      return null;
    }
  }

  function uniqueId(): string {
    const alphabet =
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const size = 15;
    const nanoid = customAlphabet(alphabet, size);
    return nanoid();
  }

  /**
   * @swagger
   * /views:
   *   get:
   *     parameters:
   *       - description: Session token used for authorization
   *         in: header
   *         name: x-auth-sso-token
   *         required: true
   *         schema:
   *           type: string
   *     produces:
   *       - application/json
   *     responses:
   *       200:
   *         description: A list of objects with metadata (id, meta, and name properties) for each UI view in the database
   *     summary: Returns the complete list of UI views in the database
   *     tags:
   *       - Views
   */
  app.get('/views', auth, async (_, res) => {
    const { rows = [] } = await db.query(`
      SELECT view
      FROM ui.view
      ORDER BY view->'meta'->>'timeUpdated' DESC;
    `);
    const views = rows.map(({ view }) => ({
      id: view.id,
      meta: view.meta,
      name: view.name,
    }));

    res.json(views);
  });

  /**
   * @swagger
   * /view/latest:
   *   get:
   *     parameters:
   *       - description: Session token used for authorization
   *         in: header
   *         name: x-auth-sso-token
   *         required: true
   *         schema:
   *           type: string
   *     produces:
   *       - application/json
   *     responses:
   *       200:
   *         description: View or null
   *     summary: Returns the last view updated by the user, or the most recently created system view
   *     tags:
   *       - Views
   */
  app.get('/view/latest', auth, async (_, res) => {
    const { locals } = res;
    const { username = '' } = locals;
    const view = await latestView(username);
    res.json({
      message: 'Latest view',
      success: true,
      view,
    });
  });

  /**
   * @swagger
   * /view/{id}:
   *   get:
   *     parameters:
   *       - description: Session token used for authorization
   *         in: header
   *         name: x-auth-sso-token
   *         required: true
   *         schema:
   *           type: string
   *       - description: Id of the view to return
   *         in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     produces:
   *       - application/json
   *     responses:
   *       200:
   *         description: GetViewResponse
   *     summary: Returns a view by id
   *     tags:
   *       - Views
   */
  app.get('/view/:id', auth, async (req, res) => {
    const { params } = req;
    const { id } = params;

    const { rows = [], rowCount } = await db.query(`
      SELECT view
      FROM ui.view
      WHERE id = '${id}';
    `);

    if (rowCount > 0) {
      const [{ view }] = rows;
      res.json({
        message: 'View found',
        success: true,
        view,
      });
    } else {
      res.json({
        message: `View not found`,
        success: false,
        view: null,
      });
    }
  });

  /**
   * @swagger
   * /view/{id}:
   *   delete:
   *     parameters:
   *       - description: Session token used for authorization
   *         in: header
   *         name: x-auth-sso-token
   *         required: true
   *         schema:
   *           type: string
   *       - description: Id of the view to delete
   *         in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     produces:
   *       - application/json
   *     responses:
   *       200:
   *         description: DeleteViewResponse
   *     summary: Deletes a view by id
   *     tags:
   *       - Views
   */
  app.delete('/view/:id', auth, async (req, res) => {
    const { locals } = res;
    const { username = '' } = locals;
    const { params } = req;
    const { id } = params;

    const { rowCount } = await db.query(`
      DELETE FROM ui.view
      WHERE id = '${id}'
      AND view->'meta'->>'owner' = '${username}';
    `);

    if (rowCount > 0) {
      const nextView = await latestView(username);
      res.json({
        message: 'View deleted successfully',
        nextView,
        success: true,
      });
    } else {
      res.json({
        message: `Unable to delete view with ID: ${id}`,
        nextView: null,
        success: false,
      });
    }
  });

  /**
   * @swagger
   * /view/{id}:
   *   put:
   *     consumes:
   *       - application/json
   *     parameters:
   *       - description: Session token used for authorization
   *         in: header
   *         name: x-auth-sso-token
   *         required: true
   *         schema:
   *           type: string
   *       - description: Id of the view to update
   *         in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: string
   *     produces:
   *       - application/json
   *     requestBody:
   *       description: View JSON
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *     responses:
   *       200:
   *         description: UpdateViewResponse
   *     summary: Updates a view by id
   *     tags:
   *       - Views
   */
  app.put('/view/:id', auth, async (req, res) => {
    const { locals } = res;
    const { username = '' } = locals;
    const { body, params } = req;
    const { view: updatedView } = body;
    const { id } = params;

    const { rows } = await db.query(`
      SELECT view
      FROM ui.view
      WHERE id='${id}'
      AND view->'meta'->>'owner' = '${username}';
    `);
    const [{ view: currentView }] = rows;
    const now = Date.now();
    const view = JSON.stringify({
      ...updatedView,
      meta: {
        ...currentView.meta,
        timeUpdated: now,
      },
    });
    const { rowCount } = await db.query(`
      UPDATE ui.view
      SET view='${view}'
      WHERE id='${id}'
      AND view->'meta'->>'owner' = '${username}';
    `);

    if (rowCount > 0) {
      res.json({
        message: `${id} updated`,
        success: true,
      });
    } else {
      res.json({
        message: `${id} not updated`,
        success: false,
      });
    }
  });

  /**
   * @swagger
   * /view:
   *   post:
   *     consumes:
   *       - application/json
   *     parameters:
   *       - description: Session token used for authorization
   *         in: header
   *         name: x-auth-sso-token
   *         required: true
   *         schema:
   *           type: string
   *     produces:
   *       - application/json
   *     requestBody:
   *       description: View JSON
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *     responses:
   *       200:
   *         description: CreateViewResponse
   *     summary: Creates a new view
   *     tags:
   *       - Views
   */
  app.post('/view', auth, async (req, res) => {
    const { locals } = res;
    const { username = '' } = locals;
    const { body } = req;
    const { name, view: newView } = body;

    const id = uniqueId();
    const now = Date.now();
    const { VERSION } = getEnv();
    const meta = {
      owner: username,
      timeCreated: now,
      timeUpdated: now,
      version: VERSION,
    };
    const view = { ...newView, id, meta, name };
    const viewStr = JSON.stringify({ ...newView, id, meta, name });

    const { rowCount } = await db.query(`
      INSERT INTO ui.view (id, view)
      VALUES ('${id}', '${viewStr}');
    `);

    if (rowCount > 0) {
      res.json({
        message: `${id} created`,
        success: true,
        view,
      });
    } else {
      res.json({
        message: `${id} not created`,
        success: false,
        view: null,
      });
    }
  });
};
