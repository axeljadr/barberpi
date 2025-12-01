import express from "express";
import cors from "cors";
import mssql from "mssql";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import multer from "multer";
import fs from "fs";
import { fileURLToPath } from "url";
const app = express();
const PORT = 4000;
const SECRET = "barberpi_secret_2024";

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "uploads"));
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const baseName = path.basename(file.originalname, ext);
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, baseName + "-" + uniqueSuffix + ext);
  },
});
const storagePerfil = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/fotosdeperfil/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "perfil-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const uploadPerfil = multer({ storage: storagePerfil });
const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Solo se permiten archivos de imagen"));
    }
    cb(null, true);
  },
});

const dbConfig = {
  server: process.env.DB_HOST || "barberpisql.database.windows.net",
  port: parseInt(process.env.DB_PORT || "1433", 10),
  database: process.env.DB_NAME || "barberPi",
  user: process.env.DB_USER || "axelrivera",
  password: process.env.DB_PASS || "12345678Julio",
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

let pool = null;

async function conectarDB() {
  if (!pool) {
    pool = mssql
      .connect(dbConfig)
      .then((pool) => {
        console.log("Conectado a SQL Server");
        return pool;
      })
      .catch((err) => {
        console.error("Error al conectar: ", err);
        pool = null;
        throw err;
      });
  }
  return pool;
}

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Formato de token inválido" });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.usuario = decoded; // { id, email, rol }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "templates", "login.html"));
});
app.post("/api/auth/registro", async (req, res) => {
  const { nombre, email, contraseña } = req.body;

  if (!nombre || !email || !contraseña) {
    return res.status(400).json({ error: "Faltan datos obligatorios" });
  }

  try {
    const pool = await conectarDB();

    const existe = await pool
      .request()
      .input("email", mssql.NVarChar, email)
      .query("SELECT * FROM usuarios WHERE email = @email");

    if (existe.recordset.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado" });
    }

    const hashed = await bcrypt.hash(contraseña, 10);

    await pool
      .request()
      .input("nombre", mssql.NVarChar, nombre)
      .input("email", mssql.NVarChar, email)
      .input("contraseña", mssql.NVarChar, hashed)
      .query(
        "INSERT INTO usuarios (nombre, email, contraseña) VALUES (@nombre, @email, @contraseña)"
      );

    res.json({ mensaje: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error en /registro:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, contraseña } = req.body;

  if (!email || !contraseña) {
    return res
      .status(400)
      .json({ error: "Email y contraseña son obligatorios" });
  }

  try {
    const pool = await conectarDB();

    const result = await pool
      .request()
      .input("email", mssql.NVarChar, email)
      .query("SELECT * FROM usuarios WHERE email = @email");

    const usuario = result.recordset[0];
    if (!usuario) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const isMatch = await bcrypt.compare(contraseña, usuario.contraseña);
    if (!isMatch) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      {
        id: usuario.id_usuario,
        email: usuario.email,
        rol: usuario.rol,
      },
      SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      mensaje: "Login exitoso",
      token,
      usuario: {
        id_usuario: usuario.id_usuario,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
      },
    });
  } catch (error) {
    console.error("Error en /login:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.get("/api/auth/perfil", verificarToken, async (req, res) => {
  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_usuario", mssql.Int, req.usuario.id).query(`
        SELECT 
          id_usuario,
          nombre,
          apellidoP,
          apellidoM,
          edad,
          email,
          telefono,
          foto_perfil,
          rol
        FROM usuarios
        WHERE id_usuario = @id_usuario
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json(result.recordset[0]);
  } catch (error) {
    console.error("Error en GET /perfil:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.put("/api/auth/perfil", verificarToken, async (req, res) => {
  const {
    nombre,
    apellidoP,
    apellidoM,
    edad,
    email,
    telefono,
    foto_perfil,
    rol,
  } = req.body;

  try {
    const pool = await conectarDB();
    await pool
      .request()
      .input("id", mssql.Int, req.usuario.id)
      .input("nombre", mssql.NVarChar, nombre)
      .input("apellidoP", mssql.NVarChar, apellidoP || null)
      .input("apellidoM", mssql.NVarChar, apellidoM || null)
      .input("edad", mssql.Int, edad || null)
      .input("email", mssql.NVarChar, email)
      .input("telefono", mssql.NVarChar, telefono || null)
      .input("foto_perfil", mssql.NVarChar, foto_perfil || null)
      .input("rol", mssql.NVarChar, rol || "cliente").query(`
        UPDATE usuarios
        SET 
          nombre = @nombre,
          apellidoP = @apellidoP,
          apellidoM = @apellidoM,
          edad = @edad,
          email = @email,
          telefono = @telefono,
          foto_perfil = @foto_perfil,
          rol = @rol
        WHERE id_usuario = @id
      `);

    res.json({ mensaje: "Perfil actualizado correctamente" });
  } catch (error) {
    console.error("Error en PUT /perfil:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.put(
  "/api/auth/perfil/foto",
  verificarToken,
  uploadPerfil.single("foto"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No se recibió ninguna imagen" });
    }

    const url_foto = `/uploads/fotosdeperfil/${req.file.filename}`;

    try {
      const pool = await conectarDB();

      const userResult = await pool
        .request()
        .input("id_usuario", mssql.Int, req.usuario.id).query(`
          SELECT foto_perfil 
          FROM usuarios 
          WHERE id_usuario = @id_usuario
        `);

      const fotoAnterior =
        userResult.recordset.length > 0
          ? userResult.recordset[0].foto_perfil
          : null;

      await pool
        .request()
        .input("id_usuario", mssql.Int, req.usuario.id)
        .input("foto_perfil", mssql.NVarChar(255), url_foto).query(`
          UPDATE usuarios
          SET foto_perfil = @foto_perfil
          WHERE id_usuario = @id_usuario
        `);

      if (
        fotoAnterior &&
        fotoAnterior.startsWith("/uploads/fotosdeperfil/") &&
        fotoAnterior !== url_foto
      ) {
        try {
          const filePath = path.join(
            __dirname,
            fotoAnterior.replace("/uploads/", "uploads/")
          );
          fs.unlink(filePath, (err) => {
            if (err)
              console.warn("No se pudo borrar foto anterior:", err.message);
          });
        } catch (e) {
          console.warn("Error al intentar eliminar foto anterior:", e);
        }
      }

      res.json({
        mensaje: "Foto de perfil actualizada correctamente",
        foto_perfil: url_foto,
      });
    } catch (error) {
      console.error("Error al actualizar foto de perfil:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);

app.post(
  "/api/catalogo",
  verificarToken,
  upload.single("imagen"),
  async (req, res) => {
    if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
      return res
        .status(403)
        .json({ error: "Solo barberos y admins pueden subir imágenes" });
    }

    const { nombre, descripcion, nombre_barber, nombre_barber_ref } = req.body;

    if (!nombre || !descripcion) {
      return res
        .status(400)
        .json({ error: "Nombre y descripción son obligatorios" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "Debes seleccionar una imagen" });
    }

    const url_imagen = `/uploads/${req.file.filename}`;

    try {
      const pool = await conectarDB();

      const usuarioResult = await pool
        .request()
        .input("id_usuario", mssql.Int, req.usuario.id).query(`
          SELECT nombre 
          FROM usuarios 
          WHERE id_usuario = @id_usuario
        `);

      const nombreUsuario =
        usuarioResult.recordset.length > 0
          ? usuarioResult.recordset[0].nombre
          : "Usuario desconocido";

      let nombre_barber_final;

      if (req.usuario.rol === "barbero") {
        nombre_barber_final = nombreUsuario;
      } else {
        nombre_barber_final =
          (nombre_barber && nombre_barber.trim()) ||
          (nombre_barber_ref && nombre_barber_ref.trim()) ||
          nombreUsuario;
      }

      const result = await pool
        .request()
        .input("nombre", mssql.NVarChar(100), nombre)
        .input("url_imagen", mssql.VarChar, url_imagen)
        .input("descripcion", mssql.Text, descripcion)
        .input("nombre_barber", mssql.NVarChar(100), nombre_barber_final)
        .query(`
          INSERT INTO ImagenCatalogo (nombre, url_imagen, descripcion, nombre_barber)
          OUTPUT INSERTED.id_foto, INSERTED.fecha_subida
          VALUES (@nombre, @url_imagen, @descripcion, @nombre_barber)
        `);

      const inserted = result.recordset[0];

      res.json({
        mensaje: "Imagen subida correctamente",
        imagen: {
          id_foto: inserted.id_foto,
          nombre,
          url_imagen,
          descripcion,
          nombre_barber: nombre_barber_final,
          fecha_subida: inserted.fecha_subida,
        },
      });
    } catch (error) {
      console.error("Error al subir imagen:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);
app.get("/api/catalogo/mis-trabajos", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res
      .status(403)
      .json({ error: "Solo barberos y admins pueden ver este catálogo" });
  }

  try {
    const pool = await conectarDB();

    const usuarioResult = await pool
      .request()
      .input("id_usuario", mssql.Int, req.usuario.id).query(`
        SELECT nombre 
        FROM usuarios 
        WHERE id_usuario = @id_usuario
      `);

    let query;
    const request = pool.request();
    query = `
        SELECT 
          ic.id_foto,
          ic.nombre,
          ic.url_imagen,
          ic.descripcion,
          ic.nombre_barber,
          ic.fecha_subida
        FROM ImagenCatalogo ic
        ORDER BY ic.fecha_subida DESC
      `;
    const result = await request.query(query);
    res.json(result.recordset);
  } catch (error) {
    console.error("Error al obtener catálogo:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});
app.put(
  "/api/catalogo/:id_foto",
  verificarToken,
  upload.single("imagen"),
  async (req, res) => {
    if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
      return res
        .status(403)
        .json({ error: "Solo barberos y admins pueden actualizar imágenes" });
    }

    const { id_foto } = req.params;
    const { nombre, descripcion, nombre_barber_ref } = req.body;

    if (!nombre || !descripcion) {
      return res
        .status(400)
        .json({ error: "Nombre y descripción son obligatorios" });
    }

    try {
      const pool = await conectarDB();

      const usuarioResult = await pool
        .request()
        .input("id_usuario", mssql.Int, req.usuario.id).query(`
          SELECT nombre 
          FROM usuarios 
          WHERE id_usuario = @id_usuario
        `);

      const nombreUsuario =
        usuarioResult.recordset.length > 0
          ? usuarioResult.recordset[0].nombre
          : null;

      const check = await pool.request().input("id_foto", mssql.Int, id_foto)
        .query(`
          SELECT nombre_barber, url_imagen
          FROM ImagenCatalogo
          WHERE id_foto = @id_foto
        `);

      if (check.recordset.length === 0) {
        return res.status(404).json({ error: "Imagen no encontrada" });
      }

      const registro = check.recordset[0];

      if (
        req.usuario.rol === "barbero" &&
        registro.nombre_barber !== nombreUsuario
      ) {
        return res.status(403).json({
          error: "No estás autorizado para editar este trabajo",
        });
      }

      let nombre_barber = registro.nombre_barber;

      if (req.usuario.rol === "barbero") {
        nombre_barber = nombreUsuario;
      } else if (req.usuario.rol === "admin") {
        if (nombre_barber_ref && nombre_barber_ref.trim() !== "") {
          nombre_barber = nombre_barber_ref.trim();
        }
      }

      let nuevaUrlImagen = registro.url_imagen;
      if (req.file) {
        nuevaUrlImagen = `/uploads/${req.file.filename}`;

        try {
          const filePath = path.join(
            __dirname,
            registro.url_imagen.replace("/uploads/", "uploads/")
          );
          fs.unlink(filePath, (err) => {
            if (err)
              console.warn("No se pudo borrar archivo anterior:", err.message);
          });
        } catch (e) {
          console.warn("Error al intentar eliminar archivo anterior:", e);
        }
      }

      await pool
        .request()
        .input("id_foto", mssql.Int, id_foto)
        .input("nombre", mssql.NVarChar(100), nombre)
        .input("url_imagen", mssql.VarChar, nuevaUrlImagen)
        .input("descripcion", mssql.Text, descripcion)
        .input("nombre_barber", mssql.NVarChar(100), nombre_barber).query(`
          UPDATE ImagenCatalogo
          SET nombre = @nombre,
              url_imagen = @url_imagen,
              descripcion = @descripcion,
              nombre_barber = @nombre_barber
          WHERE id_foto = @id_foto
        `);

      res.json({
        mensaje: "Trabajo actualizado correctamente",
        imagen: {
          id_foto,
          nombre,
          url_imagen: nuevaUrlImagen,
          descripcion,
          nombre_barber,
        },
      });
    } catch (error) {
      console.error("Error al actualizar imagen:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);
app.delete("/api/catalogo/:id_foto", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res
      .status(403)
      .json({ error: "Solo barberos y admins pueden eliminar imágenes" });
  }

  const { id_foto } = req.params;

  try {
    const pool = await conectarDB();

    const usuarioResult = await pool
      .request()
      .input("id_usuario", mssql.Int, req.usuario.id).query(`
        SELECT nombre 
        FROM usuarios 
        WHERE id_usuario = @id_usuario
      `);

    const nombreUsuario =
      usuarioResult.recordset.length > 0
        ? usuarioResult.recordset[0].nombre
        : null;

    const check = await pool.request().input("id_foto", mssql.Int, id_foto)
      .query(`
        SELECT nombre_barber, url_imagen 
        FROM ImagenCatalogo 
        WHERE id_foto = @id_foto
      `);

    if (check.recordset.length === 0) {
      return res.status(404).json({ error: "Imagen no encontrada" });
    }

    const registro = check.recordset[0];

    if (
      req.usuario.rol === "barbero" &&
      registro.nombre_barber !== nombreUsuario
    ) {
      return res.status(403).json({
        error: "No estás autorizado para eliminar este trabajo",
      });
    }

    const url_imagen = registro.url_imagen;

    await pool
      .request()
      .input("id_foto", mssql.Int, id_foto)
      .query(`DELETE FROM ImagenCatalogo WHERE id_foto = @id_foto`);

    try {
      const filePath = path.join(
        __dirname,
        url_imagen.replace("/uploads/", "uploads/")
      );
      fs.unlink(filePath, (err) => {
        if (err) console.warn("No se pudo borrar archivo:", err.message);
      });
    } catch (e) {
      console.warn("Error al borrar archivo:", e);
    }

    res.json({ mensaje: "Imagen eliminada correctamente" });
  } catch (error) {
    console.error("Error al eliminar imagen:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Crear un mensaje nuevo
app.post("/api/mensajes", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res
      .status(403)
      .json({ error: "Solo barberos y admins pueden crear mensajes" });
  }

  const { mensaje, tipo } = req.body;
  const tiposPermitidos = ["info", "ocupado", "trabajando"];

  if (!mensaje || !mensaje.trim()) {
    return res.status(400).json({ error: "El mensaje no puede estar vacío" });
  }

  const tipoFinal = tiposPermitidos.includes(tipo) ? tipo : "info";

  try {
    const pool = await conectarDB();

    const result = await pool
      .request()
      .input("id_barbero", mssql.Int, req.usuario.id)
      .input("mensaje", mssql.NVarChar(700), mensaje.trim())
      .input("tipo", mssql.VarChar(20), tipoFinal).query(`
        INSERT INTO Mensajes (id_barbero, mensaje, tipo, activo)
        OUTPUT INSERTED.id_mensaje, INSERTED.creado_en
        VALUES (@id_barbero, @mensaje, @tipo, 1)
      `);

    const inserted = result.recordset[0];

    res.json({
      mensaje: "Mensaje creado",
      data: {
        id_mensaje: inserted.id_mensaje,
        id_barbero: req.usuario.id,
        mensaje: mensaje.trim(),
        tipo: tipoFinal,
        activo: true,
        creado_en: inserted.creado_en,
      },
    });
  } catch (error) {
    console.error("Error al crear mensaje:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Mensajes del barbero logueado (incluye activos/inactivos)
app.get("/api/mensajes/mis-mensajes", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res
      .status(403)
      .json({ error: "Solo barberos y admins pueden ver estos mensajes" });
  }

  try {
    const pool = await conectarDB();

    const result = await pool
      .request()
      .input("id_barbero", mssql.Int, req.usuario.id).query(`
        SELECT id_mensaje, id_barbero, mensaje, tipo, activo, creado_en
        FROM Mensajes
        WHERE id_barbero = @id_barbero and activo = 1
        ORDER BY creado_en DESC
      `);

    res.json(result.recordset);
  } catch (error) {
    console.error("Error al obtener mensajes:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Editar contenido y tipo
app.put("/api/mensajes/:id_mensaje", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res
      .status(403)
      .json({ error: "Solo barberos y admins pueden editar mensajes" });
  }

  const id_mensaje = parseInt(req.params.id_mensaje, 10);
  if (isNaN(id_mensaje)) {
    return res.status(400).json({ error: "id_mensaje inválido" });
  }

  const { mensaje, tipo } = req.body;
  const tiposPermitidos = ["info", "ocupado", "trabajando"];

  if (!mensaje || !mensaje.trim()) {
    return res.status(400).json({ error: "El mensaje no puede estar vacío" });
  }

  const tipoFinal = tiposPermitidos.includes(tipo) ? tipo : "info";

  try {
    const pool = await conectarDB();

    const result = await pool
      .request()
      .input("id_mensaje", mssql.Int, id_mensaje)
      .input("id_barbero", mssql.Int, req.usuario.id)
      .input("mensaje", mssql.NVarChar(700), mensaje.trim())
      .input("tipo", mssql.VarChar(20), tipoFinal).query(`
        UPDATE Mensajes
        SET mensaje = @mensaje,
            tipo = @tipo
        WHERE id_mensaje = @id_mensaje
          AND id_barbero = @id_barbero;

        SELECT id_mensaje, id_barbero, mensaje, tipo, activo, creado_en
        FROM Mensajes
        WHERE id_mensaje = @id_mensaje
          AND id_barbero = @id_barbero;
      `);

    if (!result.recordset.length) {
      return res.status(404).json({ error: "Mensaje no encontrado" });
    }

    res.json({ mensaje: "Mensaje actualizado", data: result.recordset[0] });
  } catch (error) {
    console.error("Error al actualizar mensaje:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Cambiar estado activo (borrado lógico)
app.patch(
  "/api/mensajes/:id_mensaje/activo",
  verificarToken,
  async (req, res) => {
    if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
      return res.status(403).json({
        error: "Solo barberos y admins pueden cambiar estado de mensajes",
      });
    }

    const id_mensaje = parseInt(req.params.id_mensaje, 10);
    if (isNaN(id_mensaje)) {
      return res.status(400).json({ error: "id_mensaje inválido" });
    }

    const { activo } = req.body;
    const activoBool = Boolean(activo);

    try {
      const pool = await conectarDB();

      const result = await pool
        .request()
        .input("id_mensaje", mssql.Int, id_mensaje)
        .input("id_barbero", mssql.Int, req.usuario.id)
        .input("activo", mssql.Bit, activoBool).query(`
        UPDATE Mensajes
        SET activo = @activo
        WHERE id_mensaje = @id_mensaje
          AND id_barbero = @id_barbero;

        SELECT id_mensaje, id_barbero, mensaje, tipo, activo, creado_en
        FROM Mensajes
        WHERE id_mensaje = @id_mensaje
          AND id_barbero = @id_barbero;
      `);

      if (!result.recordset.length) {
        return res.status(404).json({ error: "Mensaje no encontrado" });
      }

      res.json({
        mensaje: "Estado de mensaje actualizado",
        data: result.recordset[0],
      });
    } catch (error) {
      console.error("Error al cambiar estado de mensaje:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);

// Mensajes activos para mostrar a clientes
app.get("/api/mensajes/publico", verificarToken, async (req, res) => {
  try {
    const pool = await conectarDB();

    const result = await pool.request().query(`
      SELECT m.id_mensaje,
             m.id_barbero,
             u.nombre AS nombre_barber,
             m.mensaje,
             m.tipo,
             m.activo,
             m.creado_en
      FROM Mensajes m
      JOIN Usuarios u ON m.id_barbero = u.id_usuario
      WHERE m.activo = 1
      ORDER BY m.creado_en DESC
    `);

    res.json(result.recordset);
  } catch (error) {
    console.error("Error al obtener mensajes públicos:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});
app.get("/api/catalogo/por-barber", verificarToken, async (req, res) => {
  let nombre_barber = req.query.nombre_barber;

  if (nombre_barber == null) {
    return res.status(400).json({ error: "nombre_barber es requerido" });
  }

  nombre_barber = String(nombre_barber).trim();

  if (!nombre_barber) {
    return res
      .status(400)
      .json({ error: "nombre_barber no puede estar vacío" });
  }

  console.log("nombre_barber (string) =", nombre_barber);

  try {
    const pool = await conectarDB();

    const maxLen = 100;
    if (nombre_barber.length > maxLen) {
      nombre_barber = nombre_barber.substring(0, maxLen);
    }

    const result = await pool
      .request()
      .input("nombre_barber", mssql.NVarChar(maxLen), nombre_barber).query(`
        SELECT id_foto, nombre, url_imagen, descripcion, nombre_barber, fecha_subida
        FROM ImagenCatalogo
        WHERE nombre_barber = @nombre_barber
        ORDER BY fecha_subida DESC
      `);

    console.log(
      `Catalogo por barbero "${nombre_barber}" → filas:`,
      result.recordset.length
    );

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error al obtener catálogo por barbero:", error);
    return res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: String(error) });
  }
});

app.get("/api/catalogo/historial", verificarToken, async (req, res) => {
  try {
    const pool = await conectarDB();
    const result = await pool.request().query(`
      SELECT TOP 40 id_foto, nombre, url_imagen, descripcion, nombre_barber, fecha_subida
      FROM ImagenCatalogo
      ORDER BY fecha_subida DESC
    `);

    res.json(result.recordset);
  } catch (error) {
    console.error("Error al obtener historial catálogo:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.get("/api/horario-semanal", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res.status(403).json({ error: "Acceso denegado" });
  }

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_barbero", mssql.Int, req.usuario.id).query(`
      SELECT dia_semana, hora_inicio, hora_fin, duracion_minutos, activo
      FROM HorarioSemanalBarbero
      WHERE id_barbero = @id_barbero
      ORDER BY dia_semana
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Error al obtener horario semanal:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.get("/api/horario-dia", verificarToken, async (req, res) => {
  try {
    const { fecha } = req.query;
    if (!fecha) {
      return res.status(400).json({ error: "Se requiere fecha" });
    }

    const id_barbero = req.usuario.id;
    const pool = await conectarDB();

    const fechaObj = new Date(fecha + "T00:00:00");
    const diaSemana = fechaObj.getDay();

    const sem = await pool
      .request()
      .input("id_barbero", mssql.Int, id_barbero)
      .input("dia_semana", mssql.TinyInt, diaSemana).query(`
        SELECT hora_inicio, hora_fin, duracion_minutos
        FROM HorarioSemanalBarbero
        WHERE id_barbero = @id_barbero 
          AND dia_semana = @dia_semana 
          AND activo = 1
      `);

    const bloques = sem.recordset;

    if (bloques.length === 0) {
      return res.json({
        horarioTipo: "semanal",
        slots: [],
      });
    }

    const slots = [];

    for (const b of bloques) {
      const dur = b.duracion_minutos || 45;

      const inicioStr = (b.hora_inicio || "").slice(0, 5);
      const finStr = (b.hora_fin || "").slice(0, 5);

      if (!inicioStr || !finStr || inicioStr.length < 4 || finStr.length < 4) {
        continue;
      }

      const [hIni, mIni] = inicioStr.split(":").map((n) => parseInt(n));
      const [hFin, mFin] = finStr.split(":").map((n) => parseInt(n));

      let inicioMin = hIni * 60 + mIni;
      const finMin = hFin * 60 + mFin;

      while (inicioMin < finMin) {
        const hh = String(Math.floor(inicioMin / 60)).padStart(2, "0");
        const mm = String(inicioMin % 60).padStart(2, "0");
        slots.push({
          hora: `${hh}:${mm}`, // "HH:MM"
          disponible: true,
        });
        inicioMin += dur;
      }
    }

    // 4) Citas del día para ese barbero
    const citasRes = await pool
      .request()
      .input("id_barbero", mssql.Int, id_barbero)
      .input("fecha", mssql.Date, fecha).query(`
        SELECT hora, estado, id_usuario, servicio
        FROM Citas
        WHERE id_barbero = @id_barbero
          AND fecha = @fecha   
          AND estado NOT IN ('cancelada')
      `);

    const citas = citasRes.recordset || [];

    const citasPorHora = new Map();
    for (const c of citas) {
      const horaCita = c.hora.slice(0, 5);
      citasPorHora.set(horaCita, c);
    }

    const slotsFinal = slots.map((s) => {
      const cita = citasPorHora.get(s.hora);
      return {
        ...s,
        disponible: !cita,
      };
    });

    res.json({
      horarioTipo: "semanal",
      slots: slotsFinal,
    });
  } catch (err) {
    console.error("Error en /api/horario-dia:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

app.get("/api/citas-dia", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res.status(403).json({ error: "Acceso denegado" });
  }

  const { fecha } = req.query;

  if (!fecha) {
    return res.status(400).json({ error: "Fecha requerida" });
  }

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_barbero", mssql.Int, req.usuario.id)
      .input("fecha", mssql.Date, fecha).query(`
        SELECT c.id_cita, c.hora, c.estado,
        s.nombre AS servicio_nombre, 
        c.notas,
      u.nombre AS cliente_nombre
    FROM Citas c
    LEFT JOIN Usuarios u ON c.id_usuario = u.id_usuario
    LEFT JOIN Servicios s ON c.servicio = s.id_servicio
    WHERE c.id_barbero = @id_barbero AND c.fecha = @fecha
          AND c.estado NOT IN ('cancelada')
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Error al obtener citas del día:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// POST /api/marcar-dia - marcar día completo con mensaje
app.post("/api/marcar-dia", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res.status(403).json({ error: "Acceso denegado" });
  }

  const { fecha, tipo, mensaje } = req.body;

  if (!fecha || !tipo) {
    return res.status(400).json({ error: "Datos incompletos" });
  }

  try {
    const pool = await conectarDB();

    // Insertar mensaje en MensajesCalendario
    await pool
      .request()
      .input("id_barbero", mssql.Int, req.usuario.id)
      .input("fecha", mssql.Date, fecha)
      .input("mensaje", mssql.NVarChar(500), mensaje || tipo)
      .input("tipo", mssql.VarChar(20), tipo).query(`
        INSERT INTO MensajesCalendario (id_barbero, fecha, mensaje, tipo, activo)
        VALUES (@id_barbero, @fecha, @mensaje, @tipo, 1)
      `);

    res.json({ mensaje: "Día marcado correctamente" });
  } catch (err) {
    console.error("Error al marcar día:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// POST /api/marcar-slot - marcar slot individual como ocupado
app.post("/api/marcar-slot", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res.status(403).json({ error: "Acceso denegado" });
  }

  const { fecha, hora, tipo } = req.body;

  if (!fecha || !hora) {
    return res.status(400).json({ error: "Datos incompletos" });
  }

  try {
    const pool = await conectarDB();
    const idUsuario = req.usuario.id;
    const idBarbero = req.usuario.id;
    const servicioResult = await pool.request().query(`
      SELECT TOP 1 id_servicio FROM Servicios ORDER BY id_servicio
    `);
    if (servicioResult.recordset.length === 0) {
      return res.status(500).json({ error: "No hay servicios definidos" });
    }

    const idServicio = servicioResult.recordset[0].id_servicio;

    await pool
      .request()
      .input("id_usuario", mssql.Int, idUsuario)
      .input("id_barbero", mssql.Int, idBarbero)
      .input("fecha", mssql.Date, fecha)
      .input("hora", mssql.VarChar(8), hora)
      .input("servicio", mssql.Int, idServicio)
      .input("estado", mssql.VarChar(20), "confirmada").query(`
        INSERT INTO Citas (id_usuario, id_barbero, fecha, hora, servicio, estado)
        VALUES (@id_usuario, @id_barbero, @fecha, @hora, @servicio, @estado)
      `);

    res.json({ mensaje: "Slot marcado" });
  } catch (err) {
    console.error("Error al marcar slot:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

app.post("/api/liberar-slot", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res.status(403).json({ error: "Acceso denegado" });
  }

  const { id_cita } = req.body;
  const id_barbero = req.usuario.id;

  if (!id_cita) {
    return res.status(400).json({ error: "id_cita requerido" });
  }

  try {
    const pool = await conectarDB();

    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_barbero", mssql.Int, id_barbero).query(`
        DELETE FROM Citas
        WHERE id_cita = @id_cita AND id_barbero = @id_barbero
      `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Slot no encontrado" });
    }

    res.json({ mensaje: "Slot liberado" });
  } catch (err) {
    console.error("Error al liberar slot:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

// GET /api/notificaciones-cliente
app.get("/api/notificaciones-cliente", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }

  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();

    // Próxima cita futura (la más cercana)
    const proximaResult = await pool
      .request()
      .input("id_usuario", mssql.Int, idCliente).query(`
        SELECT TOP 1
          id_cita,
          fecha,
          hora,
          estado
        FROM Citas
        WHERE id_usuario = @id_usuario
          AND fecha >= CAST(GETDATE() AS DATE)
          AND estado IN ('pendiente', 'confirmada')
        ORDER BY fecha ASC, hora ASC
      `);

    // Última cita pasada
    const ultimaResult = await pool
      .request()
      .input("id_usuario", mssql.Int, idCliente).query(`
        SELECT TOP 1
          id_cita,
          fecha,
          hora,
          estado
        FROM Citas
        WHERE id_usuario = @id_usuario
          AND fecha < CAST(GETDATE() AS DATE)
        ORDER BY fecha DESC, hora DESC
      `);

    const notificaciones = [];
    const hoy = new Date();
    const hoysolo = new Date(hoy.getFullYear(), hoy.getMonth(), hoy.getDate());

    // --- Próxima cita ---
    if (proximaResult.recordset.length > 0) {
      const cita = proximaResult.recordset[0];
      const fechaCita = new Date(cita.fecha);
      const citasolo = new Date(
        fechaCita.getFullYear(),
        fechaCita.getMonth(),
        fechaCita.getDate()
      );
      const diffMs = citasolo - hoysolo;
      const diffDias = diffMs / (1000 * 60 * 60 * 24);

      // 1) Notificación de que su próxima cita es a tal hora (siempre)
      notificaciones.push({
        tipo: "proxima_cita", // para pintar la tarjeta
        id_cita: cita.id_cita,
        fecha: cita.fecha,
        hora: cita.hora,
        estado: cita.estado,
      });

      // 2) Si es mañana, recordatorio un día antes
      if (diffDias === 1) {
        notificaciones.push({
          tipo: "recordatorio_un_dia_antes",
          id_cita: cita.id_cita,
          fecha: cita.fecha,
          hora: cita.hora,
          estado: cita.estado,
        });
      }
    }

    if (ultimaResult.recordset.length > 0) {
      const ultima = ultimaResult.recordset[0];
      const fechaUltima = new Date(ultima.fecha);

      const diffMs =
        hoysolo -
        new Date(
          fechaUltima.getFullYear(),
          fechaUltima.getMonth(),
          fechaUltima.getDate()
        );
      const diffDias = diffMs / (1000 * 60 * 60 * 24);

      if (diffDias >= 30) {
        notificaciones.push({
          tipo: "ultima_hace_mes",
          id_cita: ultima.id_cita,
          fecha: ultima.fecha,
          hora: ultima.hora,
          estado: ultima.estado,
        });
      }
    }

    res.json(notificaciones);
  } catch (err) {
    console.error("Error obteniendo notificaciones cliente:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});
app.get("/api/notificaciones/barbero", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "barbero" && req.usuario.rol !== "admin") {
    return res
      .status(403)
      .json({ error: "Solo barberos pueden ver estas notificaciones" });
  }

  try {
    const pool = await conectarDB();

    const result = await pool
      .request()
      .input("id_barbero", mssql.Int, req.usuario.id).query(`
        SELECT 
          c.id_cita,
          c.fecha,
          c.hora,
          c.estado,
          c.creado_en,
          u.nombre AS nombre_cliente,
          s.nombre AS nombre_servicio
        FROM Citas c
        JOIN Usuarios u ON c.id_usuario = u.id_usuario
        JOIN Servicios s ON c.servicio = s.id_servicio
        WHERE c.id_barbero = @id_barbero
          AND c.creado_en >= DATEADD(DAY, -7, GETDATE())
        ORDER BY c.creado_en DESC
      `);

    const citas = result.recordset;

    // Convertir cada cita en una "notificación" según su estado
    const notificaciones = citas.map((c) => {
      let tipo;
      let titulo;
      let mensaje;

      switch (c.estado) {
        case "pendiente":
          tipo = "nueva";
          titulo = "Nueva cita agendada";
          mensaje = `El cliente ${c.nombre_cliente} ha agendado una cita para ${c.nombre_servicio}`;
          break;
        case "cancelada":
          tipo = "cancelada";
          titulo = "Cita cancelada";
          mensaje = `${c.nombre_cliente} ha cancelado su cita para ${c.nombre_servicio}`;
          break;
        case "confirmada":
          tipo = "confirmada";
          titulo = "Cita confirmada";
          mensaje = `${c.nombre_cliente} ha confirmado su cita para ${c.nombre_servicio}`;
          break;
        case "completada":
          tipo = "completada";
          titulo = "Cita completada";
          mensaje = `Cita con ${c.nombre_cliente} para ${c.nombre_servicio} ha sido completada`;
          break;
        default:
          tipo = "nueva";
          titulo = "Actualización de cita";
          mensaje = `Cambio en la cita de ${c.nombre_cliente} para ${c.nombre_servicio}`;
      }

      return {
        id_cita: c.id_cita,
        tipo,
        titulo,
        mensaje,
        fecha_cita: c.fecha,
        hora_inicio: c.hora,
        nombre_cliente: c.nombre_cliente,
        nombre_servicio: c.nombre_servicio,
        timestamp: c.creado_en,
      };
    });

    res.json(notificaciones);
  } catch (error) {
    console.error("Error al obtener notificaciones barbero:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// POST /api/citas/:id_cita/confirmar
app.post("/api/citas/:id_cita/confirmar", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }
  const { id_cita } = req.params;
  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_usuario", mssql.Int, idCliente).query(`
          UPDATE Citas
          SET estado = 'confirmada'
          WHERE id_cita = @id_cita AND id_usuario = @id_usuario
        `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Cita no encontrada" });
    }

    res.json({ mensaje: "Cita confirmada" });
  } catch (err) {
    console.error("Error al confirmar cita:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

// POST /api/citas/:id_cita/cancelar  (negar/liberar)
app.post("/api/citas/:id_cita/cancelar", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }
  const { id_cita } = req.params;
  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_usuario", mssql.Int, idCliente).query(`
          UPDATE Citas
          SET estado = 'cancelada'
          WHERE id_cita = @id_cita AND id_usuario = @id_usuario
        `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Cita no encontrada" });
    }

    res.json({ mensaje: "Cita cancelada" });
  } catch (err) {
    console.error("Error al cancelar cita:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

// POST /api/citas/:id_cita/reagendar
// Solo marca como cancelada; el front redirige a agendar.html
app.post("/api/citas/:id_cita/reagendar", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }
  const { id_cita } = req.params;
  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_usuario", mssql.Int, idCliente).query(`
          UPDATE Citas
          SET estado = 'cancelada'
          WHERE id_cita = @id_cita AND id_usuario = @id_usuario
        `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Cita no encontrada" });
    }

    res.json({ mensaje: "Cita liberada para reagendar" });
  } catch (err) {
    console.error("Error al preparar reagenda:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

// POST /api/citas/:id_cita/confirmar
app.post("/api/citas/:id_cita/confirmar", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }
  const { id_cita } = req.params;
  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_usuario", mssql.Int, idCliente).query(`
          UPDATE Citas
          SET estado = 'confirmada'
          WHERE id_cita = @id_cita AND id_usuario = @id_usuario
        `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Cita no encontrada" });
    }

    res.json({ mensaje: "Cita confirmada" });
  } catch (err) {
    console.error("Error al confirmar cita:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

// POST /api/citas/:id_cita/cancelar  (negar/liberar)
app.post("/api/citas/:id_cita/cancelar", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }
  const { id_cita } = req.params;
  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_usuario", mssql.Int, idCliente).query(`
          UPDATE Citas
          SET estado = 'cancelada'
          WHERE id_cita = @id_cita AND id_usuario = @id_usuario
        `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Cita no encontrada" });
    }

    res.json({ mensaje: "Cita cancelada" });
  } catch (err) {
    console.error("Error al cancelar cita:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});

// POST /api/citas/:id_cita/reagendar
// Solo marca como cancelada; el front redirige a agendar.html
app.post("/api/citas/:id_cita/reagendar", verificarToken, async (req, res) => {
  if (req.usuario.rol !== "cliente") {
    return res.status(403).json({ error: "Solo clientes" });
  }
  const { id_cita } = req.params;
  const idCliente = req.usuario.id;

  try {
    const pool = await conectarDB();
    const result = await pool
      .request()
      .input("id_cita", mssql.Int, id_cita)
      .input("id_usuario", mssql.Int, idCliente).query(`
          UPDATE Citas
          SET estado = 'cancelada'
          WHERE id_cita = @id_cita AND id_usuario = @id_usuario
        `);

    if (!result.rowsAffected || result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Cita no encontrada" });
    }

    res.json({ mensaje: "Cita liberada para reagendar" });
  } catch (err) {
    console.error("Error al preparar reagenda:", err);
    res
      .status(500)
      .json({ error: "Error interno del servidor", detalle: err.message });
  }
});
function timeToHHMM(t) {
  if (!t) return null;

  // Si ya es string, lo normalizamos
  if (typeof t === "string") {
    // "HH:MM" o "HH:MM:SS"
    return t.slice(0, 5);
  }

  // Si viene como objeto Date (mssql TIME -> JS Date)
  if (t instanceof Date) {
    const hh = String(t.getHours()).padStart(2, "0");
    const mm = String(t.getMinutes()).padStart(2, "0");
    return `${hh}:${mm}`;
  }

  // Cualquier otra cosa, lo intentamos como toString
  const s = String(t);
  return s.slice(0, 5);
}
app.get("/api/horario-dia", verificarToken, async (req, res) => {
  try {
    const { fecha } = req.query;
    if (!fecha) {
      return res.status(400).json({ error: "Se requiere fecha" });
    }

    const id_barbero = req.usuario.id;
    const pool = await conectarDB();

    // 1) Día de la semana (0–6)
    const fechaObj = new Date(fecha + "T00:00:00");
    const diaSemana = fechaObj.getDay(); // 0=Dom...6=Sab

    // 2) Obtener horario semanal para ese día (ya incluye viernes)
    const sem = await pool
      .request()
      .input("id_barbero", mssql.Int, id_barbero)
      .input("dia_semana", mssql.TinyInt, diaSemana).query(`
        SELECT hora_inicio, hora_fin, duracion_minutos
        FROM HorarioSemanalBarbero
        WHERE id_barbero = @id_barbero 
          AND dia_semana = @dia_semana 
          AND activo = 1
      `);

    const bloques = sem.recordset;

    // Si no hay horario semanal -> día cerrado
    if (bloques.length === 0) {
      return res.json({
        horarioTipo: "semanal",
        slots: [],
      });
    }

    // 3) Generar slots teóricos a partir de los bloques
    const slots = [];
    for (const b of bloques) {
      const dur = b.duracion_minutos || 45;

      // Convertir lo que venga de SQL (Date/string) a "HH:MM"
      const inicioStr = timeToHHMM(b.hora_inicio); // e.g. "17:30"
      const finStr = timeToHHMM(b.hora_fin); // e.g. "20:00"

      if (!inicioStr || !finStr) continue; // por seguridad

      let [hIni, mIni] = inicioStr.split(":").map((n) => parseInt(n));
      let [hFin, mFin] = finStr.split(":").map((n) => parseInt(n));

      let inicioMin = hIni * 60 + mIni;
      const finMin = hFin * 60 + mFin;

      while (inicioMin < finMin) {
        const hh = String(Math.floor(inicioMin / 60)).padStart(2, "0");
        const mm = String(inicioMin % 60).padStart(2, "0");
        slots.push({
          hora: `${hh}:${mm}`, // "HH:MM"
          disponible: true,
        });
        inicioMin += dur;
      }
    }

    // 4) Traer citas reales de ese día para el barbero
    const citasRes = await pool
      .request()
      .input("id_barbero", mssql.Int, id_barbero)
      .input("fecha", mssql.Date, fecha).query(`
        SELECT hora, estado, cliente_nombre, servicio
        FROM Citas
        WHERE id_barbero = @id_barbero
          AND fecha = @fecha
          AND estado NOT IN ('cancelada')
      `);

    const citas = citasRes.recordset || [];

    // 5) Marcar cada slot como disponible u ocupado según las citas
    const citasPorHora = new Map();
    for (const c of citas) {
      const horaCita = c.hora.slice(0, 5); // "HH:MM"
      citasPorHora.set(horaCita, c);
    }

    const slotsFinal = slots.map((s) => {
      const cita = citasPorHora.get(s.hora);
      return {
        ...s,
        disponible: !cita,
      };
    });

    res.json({
      horarioTipo: "semanal",
      slots: slotsFinal,
    });
  } catch (err) {
    console.error("Error en /api/horario-dia:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

function formatTime(dOrStr) {
  if (typeof dOrStr === "string") {
    // asumir viene como "HH:MM:SS" o "HH:MM"
    return dOrStr.slice(0, 5);
  }
  const h = String(dOrStr.getHours()).padStart(2, "0");
  const m = String(dOrStr.getMinutes()).padStart(2, "0");
  return `${h}:${m}`;
}

const storageRef = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/referencias"),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "ref-" + unique + path.extname(file.originalname));
  },
});

const uploadReferencia = multer({
  storage: storageRef,
  limits: { fileSize: 5 * 1024 * 1024 },
});
app.get("/api/barberos", verificarToken, async (req, res) => {
  try {
    const pool = await conectarDB();
    const result = await pool.request().query(`
      SELECT id, nombre
      FROM Usuarios
      WHERE rol = 'barbero' AND activo = 1
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Error en /api/barberos:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

app.get("/api/servicios", verificarToken, async (req, res) => {
  try {
    const pool = await conectarDB();
    const result = await pool.request().query(`
      SELECT id_servicio, nombre, precio
      FROM Servicios
      ORDER BY nombre
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Error en GET /api/servicios:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

function requireBarberoOrAdmin(req, res, next) {
  const rol = req.usuario.rol;
  if (rol === "barbero" || rol === "admin") return next();
  return res.status(403).json({ error: "No autorizado" });
}

app.patch(
  "/api/citas/:id_cita/estado",
  verificarToken,
  requireBarberoOrAdmin,
  async (req, res) => {
    try {
      const { id_cita } = req.params;
      const { estado } = req.body;

      const estadosPermitidos = [
        "pendiente",
        "confirmada",
        "cancelada",
        "completada",
      ];

      if (!estado) {
        return res
          .status(400)
          .json({ error: "El campo 'estado' es requerido" });
      }

      if (!estadosPermitidos.includes(estado)) {
        return res.status(400).json({
          error: "Estado no válido",
          estadosPermitidos,
          recibido: estado,
        });
      }

      const pool = await conectarDB();

      const result = await pool
        .request()
        .input("id_cita", mssql.Int, parseInt(id_cita, 10))
        .input("estado", mssql.VarChar(14), estado).query(`
          UPDATE Citas
          SET estado = @estado
          WHERE id_cita = @id_cita
        `);

      console.log("rowsAffected:", result.rowsAffected);

      if (!result.rowsAffected || result.rowsAffected[0] === 0) {
        return res.status(404).json({ error: "Cita no encontrada" });
      }

      return res.json({ message: "Estado actualizado correctamente" });
    } catch (err) {
      console.error("Error en PATCH /api/citas/:id_cita/estado:", err);
      return res
        .status(500)
        .json({ error: "Error en el servidor", detalle: err.message });
    }
  }
);

app.patch(
  "/api/citas/:id_cita/reagendar",
  verificarToken,
  requireBarberoOrAdmin,
  async (req, res) => {
    try {
      const { id_cita } = req.params;
      const { fecha, hora } = req.body;

      if (!fecha || !hora) {
        return res.status(400).json({ error: "Fecha y hora son obligatorias" });
      }

      const pool = await conectarDB();

      // 1. Obtener info de la cita (para saber id_barbero)
      const citaRes = await pool.request().input("id_cita", mssql.Int, id_cita)
        .query(`
          SELECT id_barbero
          FROM Citas
          WHERE id_cita = @id_cita
        `);

      if (citaRes.recordset.length === 0) {
        return res.status(404).json({ error: "Cita no encontrada" });
      }

      const id_barbero = citaRes.recordset[0].id_barbero;

      // 2. Verificar que el nuevo slot esté libre
      const check = await pool
        .request()
        .input("id_barbero", mssql.Int, id_barbero)
        .input("fecha", mssql.Date, fecha)
        .input("hora", mssql.VarChar(8), hora)
        .input("id_cita", mssql.Int, id_cita).query(`
          SELECT COUNT(*) AS total
          FROM Citas
          WHERE id_barbero = @id_barbero
            AND fecha = @fecha
            AND hora = @hora
            AND estado NOT IN ('cancelada')
            AND id_cita <> @id_cita
        `);

      if (check.recordset[0].total > 0) {
        return res
          .status(400)
          .json({ error: "El nuevo horario ya está ocupado" });
      }

      // 3. Actualizar fecha y hora
      const upd = await pool
        .request()
        .input("id_cita", mssql.Int, id_cita)
        .input("fecha", mssql.Date, fecha)
        .input("hora", mssql.VarChar(8), hora).query(`
          UPDATE Citas
          SET fecha = @fecha,
              hora  = @hora
          WHERE id_cita = @id_cita
        `);

      if (upd.rowsAffected[0] === 0) {
        return res.status(404).json({ error: "Cita no encontrada" });
      }

      res.json({ message: "Cita reagendada correctamente" });
    } catch (err) {
      console.error("Error en PATCH /api/citas/:id_cita/reagendar:", err);
      res.status(500).json({ error: "Error en el servidor" });
    }
  }
);

app.post(
  "/api/servicios",
  verificarToken,
  requireBarberoOrAdmin,
  async (req, res) => {
    try {
      const { id_servicio, nombre, precio } = req.body;
      const pool = await conectarDB();

      if (!nombre || !precio) {
        return res.status(400).json({ error: "Faltan datos de servicio" });
      }

      if (id_servicio) {
        // update
        await pool
          .request()
          .input("id_servicio", mssql.Int, id_servicio)
          .input("nombre", mssql.VarChar(50), nombre)
          .input("precio", mssql.Decimal(5, 2), precio).query(`
          UPDATE Servicios
          SET nombre = @nombre,
              precio = @precio
          WHERE id_servicio = @id_servicio
        `);
      } else {
        // insert
        await pool
          .request()
          .input("nombre", mssql.VarChar(50), nombre)
          .input("precio", mssql.Decimal(5, 2), precio).query(`
          INSERT INTO Servicios (nombre, precio)
          VALUES (@nombre, @precio)
        `);
      }

      res.json({ message: "Servicio guardado" });
    } catch (err) {
      console.error("Error en POST /api/servicios:", err);
      res.status(500).json({ error: "Error en el servidor" });
    }
  }
);

app.get("/api/horario-dia-barbero", verificarToken, async (req, res) => {
  try {
    const { fecha, id_barbero } = req.query;

    if (!fecha || !id_barbero) {
      return res.status(400).json({ error: "Se requiere fecha e id_barbero" });
    }

    const pool = await conectarDB();

    const fechaObj = new Date(fecha + "T00:00:00");
    const diaSemana = fechaObj.getDay();

    console.log("DEBUG /api/horario-dia-barbero:", {
      fecha,
      id_barbero,
      diaSemana,
    });

    const sem = await pool
      .request()
      .input("id_barbero", mssql.Int, id_barbero)
      .input("dia_semana", mssql.TinyInt, diaSemana).query(`
        SELECT hora_inicio, hora_fin, duracion_minutos
        FROM HorarioSemanalBarbero
        WHERE id_barbero = @id_barbero 
          AND dia_semana = @dia_semana 
          AND activo = 1
      `);

    const bloques = sem.recordset;

    console.log("DEBUG bloques encontrados:", bloques);

    if (bloques.length === 0) {
      return res.json({ horarioTipo: "semanal", slots: [] });
    }

    const slots = [];

    for (const b of bloques) {
      const dur = b.duracion_minutos || 45;
      const inicioStr = (b.hora_inicio || "").slice(0, 5);
      const finStr = (b.hora_fin || "").slice(0, 5);

      if (!inicioStr || !finStr || inicioStr.length < 4 || finStr.length < 4) {
        continue;
      }

      const [hIni, mIni] = inicioStr.split(":").map((n) => parseInt(n));
      const [hFin, mFin] = finStr.split(":").map((n) => parseInt(n));

      let inicioMin = hIni * 60 + mIni;
      const finMin = hFin * 60 + mFin;

      while (inicioMin < finMin) {
        const hh = String(Math.floor(inicioMin / 60)).padStart(2, "0");
        const mm = String(inicioMin % 60).padStart(2, "0");
        slots.push({ hora: `${hh}:${mm}`, disponible: true });
        inicioMin += dur;
      }
    }

    console.log("DEBUG slots generados:", slots.length);

    // 👇 Usar nombres correctos de columnas
    const citasRes = await pool
      .request()
      .input("id_barbero", mssql.Int, id_barbero)
      .input("fecha", mssql.Date, fecha).query(`
        SELECT hora
        FROM Citas
        WHERE id_barbero = @id_barbero
          AND fecha = @fecha
          AND estado NOT IN ('cancelada')
      `);

    const citas = citasRes.recordset || [];
    console.log("DEBUG citas encontradas:", citas);

    const citasPorHora = new Set(citas.map((c) => c.hora.slice(0, 5)));

    const slotsFinal = slots.map((s) => ({
      ...s,
      disponible: !citasPorHora.has(s.hora),
    }));

    console.log("DEBUG slots finales:", slotsFinal);

    res.json({ horarioTipo: "semanal", slots: slotsFinal });
  } catch (err) {
    console.error("Error en /api/horario-dia-barbero:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});
app.post(
  "/api/citas",
  verificarToken,
  uploadReferencia.single("referencia_foto"),
  async (req, res) => {
    try {
      const { id_barbero, fecha, hora, id_servicio, notas, precio_estimado } =
        req.body;
      const id_usuario = req.usuario.id; // 👈 El cliente autenticado

      console.log("DEBUG POST /api/citas:", {
        id_usuario,
        id_barbero,
        fecha,
        hora,
        id_servicio,
        file: req.file,
      });

      if (!id_barbero || !fecha || !hora || !id_servicio) {
        return res.status(400).json({ error: "Faltan campos obligatorios" });
      }

      const pool = await conectarDB();
      const checkRango = await pool
        .request()
        .input("id_usuario", mssql.Int, id_usuario).query(`
          SELECT TOP 1 *
          FROM Citas
          WHERE id_usuario = @id_usuario
            AND estado IN ('pendiente','confirmada')
            AND fecha >= CAST(GETDATE() AS DATE)
            AND fecha < DATEADD(DAY, 30, CAST(GETDATE() AS DATE))
        `);

      if (checkRango.recordset.length > 0) {
        return res.status(400).json({
          error:
            "Ya tienes una cita programada en los próximos 30 días. No puedes agendar otra.",
        });
      }
      // Verificar que el slot siga disponible
      const check = await pool
        .request()
        .input("id_barbero", mssql.Int, id_barbero)
        .input("fecha", mssql.Date, fecha)
        .input("hora", mssql.VarChar(8), hora).query(`
          SELECT COUNT(*) AS total
          FROM Citas
          WHERE id_barbero = @id_barbero
            AND fecha = @fecha
            AND hora = @hora
            AND estado NOT IN ('cancelada')
        `);

      if (check.recordset[0].total > 0) {
        return res.status(400).json({ error: "Este horario ya está ocupado" });
      }

      // Construir URL pública de la foto
      let foto_url = null;
      if (req.file) {
        foto_url = `/uploads/referencias/${req.file.filename}`;
      }

      // Insertar cita con los campos exactos de tu tabla
      await pool
        .request()
        .input("id_usuario", mssql.Int, id_usuario)
        .input("id_barbero", mssql.Int, id_barbero)
        .input("fecha", mssql.Date, fecha)
        .input("hora", mssql.VarChar(8), hora)
        .input("servicio", mssql.Int, id_servicio)
        .input("notas", mssql.Text, notas || null)
        .input("precio_estimado", mssql.Decimal(5, 2), precio_estimado || null)
        .input("referencia_foto", mssql.VarChar(255), foto_url)
        .input("estado", mssql.VarChar(14), "pendiente").query(`
          INSERT INTO Citas (
            id_usuario, id_barbero, fecha, hora, servicio,
            notas, precio_estimado, referencia_foto, estado
          )
          VALUES (
            @id_usuario, @id_barbero, @fecha, @hora, @servicio,
            @notas, @precio_estimado, @referencia_foto, @estado
          )
        `);

      res.json({ message: "Cita agendada exitosamente" });
    } catch (err) {
      console.error("Error en POST /api/citas:", err);
      res.status(500).json({ error: "Error en el servidor" });
    }
  }
);
app.get("/api/citas/puede-agendar", verificarToken, async (req, res) => {
  try {
    const id_usuario = req.usuario.id;
    const pool = await conectarDB();

    const checkRango = await pool
      .request()
      .input("id_usuario", mssql.Int, id_usuario).query(`
        SELECT TOP 1 fecha, hora, servicio
        FROM Citas
        WHERE id_usuario = @id_usuario
          AND estado IN ('pendiente','confirmada')
          AND fecha >= CAST(GETDATE() AS DATE)
          AND fecha < DATEADD(DAY, 30, CAST(GETDATE() AS DATE))
        ORDER BY fecha, hora
      `);

    if (checkRango.recordset.length > 0) {
      return res.json({
        puede_agendar: false,
        cita: checkRango.recordset[0],
      });
    }

    res.json({ puede_agendar: true });
  } catch (err) {
    console.error("Error en GET /api/citas/puede-agendar:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
});
