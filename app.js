require("dotenv").config();

const express = require('express');
const app  = express();
const cors = require('cors');
const db = require('./db');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 3000;

const jwt = require('jsonwebtoken');

const EXERCISE_TYPES = ['cardio', 'strength', 'flexibility', 'balance'];

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors( { origin: 'http://localhost:5173', credentials: true }));
app.use(cookieParser());

app.get('/health', (request, response) => {
    response.status(200).json({ ok: true });
});

// middleware

function authenticateJWT(request, response, next) {
    const authHeader = request.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return response.status(401).json({ error: 'missing token' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET || 'dev-access-secret');
        request.user = { userId: decoded.userId };
        return next();
    } catch (err) {
        return response.status(401).json({ error: 'invalid or expired token' });
    }
}

// ---- AUTH ROUTES ----

// /auth/signup
app.post('/auth/signup', async (request, response, next) => {
    try {
        const { email, password } = request.body;

        if (!email || !email.trim()) {
            return response.status(400).json({ error: 'email is required' });
        }

        const trimmedEmail = email.trim();

        if (!/^[a-zA-Z][a-zA-Z0-9._]*@(?!.*\.\.)[a-zA-Z0-9]+\.(com|ca|io|edu|me|net|app|co)$/.test(trimmedEmail)) {
            return response.status(400).json({ error: 'must enter a valid email address' });
        }

        if (!password || !password.trim()) {
            return response.status(400).json({ error: 'must enter password' });
        }

        const trimmedPass = password.trim();

        if (!/^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{8,}$/.test(trimmedPass)) {
            return response.status(400).json({ error: 'password must be minimum 8 characters and include 2 uppercase, 3 lowercase, 2 digits, and 1 symbol' });
        }

        const passwordHash = await bcrypt.hash(trimmedPass, 10);

        const result = await db.query(
            `
            INSERT INTO users (email, password_hash)
            VALUES ($1, $2)
            RETURNING id, email, created_at
            `,
            [trimmedEmail, passwordHash]
        );

        return response.status(201).json({ user: result.rows[0] });
        
    } catch (err) {
        if (err.code === '23505') {
            return response.status(409).json({ error: 'email has already been taken' });
        }
        return next(err);
    }
});

// /auth/login
app.post('/auth/login', async (request, response, next) => {
    try {
        const { email, password } = request.body;

        if (!email || !email.trim()) {
            return response.status(400).json({ error: 'email is required' });
        }

        if (!password || !password.trim()) {
            return response.status(400).json({ error: 'password is required' });
        }

        const trimmedEmail = email.trim();
        const trimmedPass = password.trim();

        if (!/^[a-zA-Z][a-zA-Z0-9._]*@(?!.*\.\.)[a-zA-Z0-9]+\.(com|ca|io|edu|me|net|app|co)$/.test(trimmedEmail)) {
            return response.status(400).json({ error: 'invalid email format' });
        }

        const userResult = await db.query(
            `SELECT id, email, password_hash FROM users WHERE email = $1`, [trimmedEmail]
        );

        if (userResult.rows.length === 0) {
            return response.status(401).json({ error: 'invalid credentials' });
        }

        const user = userResult.rows[0];

        const ok = await bcrypt.compare(trimmedPass, user.password_hash);

        if (!ok) {
            return response.status(401).json({ error: 'invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id}, process.env.JWT_ACCESS_SECRET || 'dev-access-secret', { expiresIn: '15m' });

        const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret', { expiresIn: '7d' });

        const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        await db.query(
            `
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            `, [user.id, refreshTokenHash, expiresAt]
        );

        response.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return response.status(200).json({ token, user: { id: user.id, email: user.email }, })

    } catch (err) {
        return next(err);
    }
});

// /auth/refresh

app.post('/auth/refresh', async (request, response) => {
    const refresh = request.cookies.refreshToken;

    if (!refresh) {
        return response.status(401).json({ error: 'invalid token' });
    }
 
    let decoded;

    try { 
        decoded = jwt.verify(refresh, process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret');
    } catch (err) {
        return response.status(401).json({ error: 'invalid or expired token' });
    }

    const userId = decoded.userId;

    try {
        const tokenRows = await db.query(
            `
            SELECT id, token_hash
            FROM refresh_tokens
            WHERE user_id = $1
                AND revoked_at IS NULL
                AND expires_at > now()
            `, [userId]
        );

        let match = null;
        for (const row of tokenRows.rows) {
            const ok = await bcrypt.compare(refresh, row.token_hash);
            if (ok) {
                match = row;
                break;
            }
        }

        if (!match) {
            return response.status(401).json({ error: 'refresh token not recognized' });
        }

        const newAccessToken = jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET || 'dev-access-secret', { expiresIn: '15m' });

        return response.status(200).json({ token: newAccessToken });
    } catch (err) {
        console.error(err);
        return response.status(500).json({ error: 'internal server error' });
    }
});

// /auth/logout

app.post('/auth/logout', async (request, response) => {
    const refreshToken = request.cookies.refreshToken;

    // No refresh token, already effectively logged out
    if (!refreshToken) {
        return response.status(200).json({ ok: true });
    }

    let decoded;
    try {
        decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret'
        );
    } catch (err) {
        // Invalid or expired refresh token, just clear cookie
        response.clearCookie('refreshToken', { path: '/auth/refresh' });
        return response.status(200).json({ ok: true });
    }

    const userId = decoded.userId;

    try {
        const tokenRows = await db.query(
            `
            SELECT id, token_hash
            FROM refresh_tokens
            WHERE user_id = $1
              AND revoked_at IS NULL
            `,
            [userId]
        );

        const matches = await Promise.all(
            tokenRows.rows.map(row =>
                bcrypt.compare(refreshToken, row.token_hash)
                    .then(ok => ok ? row : null)
            )
        );

        const match = matches.find(Boolean);

        if (match) {
            await db.query(
                `
                UPDATE refresh_tokens
                SET revoked_at = now()
                WHERE id = $1
                `,
                [match.id]
            );
        }

        response.clearCookie('refreshToken', { path: '/auth/refresh' });
        return response.status(200).json({ ok: true });
    } catch (err) {
        console.error(err);
        response.clearCookie('refreshToken', { path: '/auth/refresh' });
        return response.status(200).json({ ok: true });
    }
});

// database vitals check
app.get('/db-check', async (request, response) => {
    try {
        const r = await db.query("SELECT now() AS now")
        response.status(200).json({ ok: true, now: r.rows[0].now });
    } catch (err) {
        response.status(500).json({ ok: false, error: err.message });
    }
});

app.get('/workouts',authenticateJWT, async (request, response) => {
    const userId = request.user.userId;

  try {
    const { favorite, type, month } = request.query;

    let typeString;
    if (type !== undefined) {
        typeString = String(type).toLowerCase();
        if (!EXERCISE_TYPES.includes(typeString)) {
            return response.status(400).json({ error: `type must be one of: ${EXERCISE_TYPES.join(', ')}` })
        }
    }

    const params = [userId];
    const conditions = ['user_id = $1'];

    // ?favorite=true
    if (favorite === 'true') {
      params.push(true);
      conditions.push(`is_favorite = $${params.length}`);
    }

    // ?type=strength (cardio|strength|flexibility|balance)
    if (typeString) {
      params.push(typeString);
      conditions.push(`exercise_type = $${params.length}`);
    }

    // ?month=YYYY-MM  (filter by performed_at within that month)
    if (month) {
      if (!/^\d{4}-\d{2}$/.test(month)) {
        return response.status(400).json({ error: 'month must be in YYYY-MM format' });
      }

      // build first day of month + first day of next month
      const start = `${month}-01`;
      const [y, m] = month.split('-').map(Number);
      const nextMonthStart =
        m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`;

      params.push(start);
      conditions.push(`performed_at >= $${params.length}`);

      params.push(nextMonthStart);
      conditions.push(`performed_at < $${params.length}`);
    }

    const sql = `
      SELECT *
      FROM workout_entries
      WHERE ${conditions.join(' AND ')}
      ORDER BY performed_at DESC, created_at DESC
    `;

    const result = await db.query(sql, params);
    return response.status(200).json({ workouts: result.rows });
  } catch (err) {
    console.error(err);
    return response.status(500).json({ error: 'internal server error' });
  }
});

app.patch('/workouts/:id/favorite',authenticateJWT, async (request, response) => {
  const userId = request.user.userId;
  const { id } = request.params;
  const { isFavorite } = request.body;

  if (typeof isFavorite !== 'boolean') {
    return response.status(400).json({ error: 'isFavorite must be boolean' });
  }

  try {
    const result = await db.query(
      `
      UPDATE workout_entries
      SET is_favorite = $1
      WHERE id = $2 AND user_id = $3
      RETURNING *
      `,
      [isFavorite, id, userId]
    );

    if (result.rows.length === 0) {
      return response.status(404).json({ error: 'workout not found' });
    }

    return response.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    return response.status(500).json({ error: 'internal server error' });
  }
});

app.patch('/workouts/:id',authenticateJWT, async (request, response) => {
  const userId = request.user.userId;
  const { id } = request.params;

  const {
    exerciseName,
    exerciseType,
    exerciseKey,
    sets,
    reps,
    performedAt,
  } = request.body;

  // At least one field must be provided
  const hasAny =
    exerciseName !== undefined ||
    exerciseType !== undefined ||
    exerciseKey !== undefined ||
    sets !== undefined ||
    reps !== undefined ||
    performedAt !== undefined;

let normalizedExerciseType;
if (exerciseType !== undefined) {
    normalizedExerciseType = String(exerciseType).toLowerCase();
  if (!EXERCISE_TYPES.includes(normalizedExerciseType)) {
    return response.status(400).json({
      error: `exerciseType must be one of: ${EXERCISE_TYPES.join(', ')}`
    });
  }
}
  if (!hasAny) {
    return response.status(400).json({ error: 'no fields provided to update' });
  }

  // Validate if provided
  let trimmedExerciseName;
  if (exerciseName !== undefined) {
    if (!exerciseName || !exerciseName.trim()) {
      return response.status(400).json({ error: 'exerciseName cannot be empty' });
    }
    trimmedExerciseName = exerciseName.trim();
  }

  let setsNum;
  if (sets !== undefined) {
    setsNum = Number(sets);
    if (!Number.isInteger(setsNum) || setsNum < 1 || setsNum > 20) {
      return response.status(400).json({ error: 'sets must be an integer between 1 and 20' });
    }
  }

  let repsNum;
  if (reps !== undefined) {
    repsNum = Number(reps);
    if (!Number.isInteger(repsNum) || repsNum < 1 || repsNum > 50) {
      return response.status(400).json({ error: 'reps must be an integer between 1 and 50' });
    }
  }

  if (performedAt !== undefined && performedAt !== null) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(performedAt)) {
      return response.status(400).json({ error: 'performedAt must be YYYY-MM-DD' });
    }
  }

  try {
    const result = await db.query(
      `
      UPDATE workout_entries
      SET
        exercise_name = COALESCE($1, exercise_name),
        exercise_type = COALESCE($2, exercise_type),
        exercise_key  = COALESCE($3, exercise_key),
        sets          = COALESCE($4, sets),
        reps          = COALESCE($5, reps),
        performed_at  = COALESCE($6, performed_at)
      WHERE id = $7 AND user_id = $8
      RETURNING *
      `,
      [
        trimmedExerciseName ?? null,
        normalizedExerciseType ?? null,
        exerciseKey ?? null,
        setsNum ?? null,
        repsNum ?? null,
        performedAt ?? null,
        id,
        userId,
      ]
    );

    if (result.rows.length === 0) {
      return response.status(404).json({ error: 'workout not found' });
    }

    return response.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    return response.status(500).json({ error: 'internal server error' });
  }
});

app.post('/workouts',authenticateJWT, async (request, response) => {
    const userId = request.user.userId;
    const {
        exerciseName,
        exerciseType,
        exerciseKey,
        sets,
        reps,
        performedAt,
    } = request.body;

    if (!exerciseName || !exerciseName.trim()) {
        return response.status(400).json({ error: 'must provide exercise name' });
    }
    
    const trimmedExerciseName = exerciseName.trim();

    if (!exerciseType) {
        return response.status(400).json({ error: 'must choose exercise type' })
    }

    const normalizedExerciseType = String(exerciseType).toLowerCase();
    if (!EXERCISE_TYPES.includes(normalizedExerciseType)) {
    return response.status(400).json({
        error: `exerciseType must be one of: ${EXERCISE_TYPES.join(', ')}`
    });
    }
        
    if (!exerciseKey) {
        return response.status(400).json({ error: 'must choose an exercise from the dropdown menu' });
    }
    
    const setsNum = Number(sets)
    const repsNum = Number(reps)

    if (!Number.isInteger(setsNum) || setsNum < 1 || setsNum > 20) {
        return response.status(400).json({ error: 'must enter number of sets' });
    }
    if (!Number.isInteger(repsNum) || repsNum < 1 || repsNum > 50) {
        return response.status(400).json({ error: 'must enter number of reps' });
    }

    try {
    const result = await db.query(`
      INSERT INTO workout_entries
      (
        user_id,
        exercise_name,
        exercise_type,
        exercise_key,
        sets,
        reps,
        performed_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, CURRENT_DATE))
      RETURNING *
      `,
      [
        userId,
        trimmedExerciseName,
        normalizedExerciseType,
        exerciseKey,
        setsNum,
        repsNum,
        performedAt,
      ]
    )
    response.status(201).json(result.rows[0]);
} catch (err) {
    response.status(500).json({ error: 'internal server error' })
}

});

app.delete('/workouts/:id',authenticateJWT, async (request, response) => {
    const { id } = request.params;
    const userId = request.user.userId;

    try {
        const result = await db.query(
        `
        DELETE FROM workout_entries
        WHERE id = $1 AND user_id = $2
        RETURNING id
        `,
        [id, userId]
        );

        if (!result.rows.length) {
            return response.status(404).json({ error: 'workout not found' });
        }

        return response.status(200).json({ deleted: true, id: result.rows[0].id });
    } catch (err) {
        console.error(err);
        return response.status(500).json({ error: 'internal server error' });
    }
 });

 // Global err handling 
app.use((err, request, response, next) => {
    console.log('GLOBAL ERROR', err);
    return response.status(500).json({ error: 'internal server error' });
});

app.listen(PORT, () => { console.log(`server is successfully running on http://127.0.0.1:${PORT}`) });