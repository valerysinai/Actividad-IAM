package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type app struct { db *sql.DB; secret []byte; origin string }
type user struct { ID, Email, FirstName, LastName, ActorType string }
type claims struct { UserID string `json:"uid"`; jwt.RegisteredClaims }

func main() {
	loadEnvFile(".env")
	url, secret := os.Getenv("DATABASE_URL"), os.Getenv("JWT_SECRET")
	if url == "" || len(secret) < 32 { log.Fatal("DATABASE_URL y JWT_SECRET (min. 32 caracteres) son obligatorios") }
	db, err := sql.Open("pgx", url); if err != nil { log.Fatal(err) }
	if err = db.Ping(); err != nil { log.Fatal(err) }; defer db.Close()
	a := &app{db: db, secret: []byte(secret), origin: env("ALLOWED_ORIGIN", "*")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("POST /api/auth/register", a.register)
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/refresh", a.refresh)
	mux.HandleFunc("POST /api/auth/forgot-password", a.forgot)
	mux.HandleFunc("POST /api/auth/reset-password", a.reset)
	mux.HandleFunc("POST /api/auth/change-password", a.auth(a.changePassword))
	mux.HandleFunc("GET /api/me", a.auth(a.me))
	log.Printf("IAM API escuchando en :%s", env("PORT", "8080"))
	log.Fatal(http.ListenAndServe(":"+env("PORT", "8080"), a.cors(mux)))
}
func loadEnvFile(path string) {
	file, err := os.Open(path); if err != nil { return }; defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" { continue }
		key, value := strings.TrimSpace(parts[0]), strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		if os.Getenv(key) == "" { _ = os.Setenv(key, value) }
	}
}
func env(k,d string) string { if v:=os.Getenv(k);v!="" {return v};return d }
func (a *app) cors(next http.Handler) http.Handler { return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){ w.Header().Set("Access-Control-Allow-Origin",a.origin);w.Header().Set("Access-Control-Allow-Headers","Authorization, Content-Type");w.Header().Set("Access-Control-Allow-Methods","GET, POST, OPTIONS");if r.Method=="OPTIONS" {w.WriteHeader(204);return};next.ServeHTTP(w,r) }) }
func jsonOut(w http.ResponseWriter, status int, v any) { w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ = json.NewEncoder(w).Encode(v) }
func fail(w http.ResponseWriter,status int,msg string){jsonOut(w,status,map[string]string{"error":msg})}
func decode(r *http.Request,v any) error { r.Body=http.MaxBytesReader(nil,r.Body,1<<20);d:=json.NewDecoder(r.Body);d.DisallowUnknownFields();return d.Decode(v) }
func validPassword(p string) bool { return len(p)>=12 && len(p)<=128 }
func randomToken() (string,error) { b:=make([]byte,32);if _,e:=rand.Read(b);e!=nil{return "",e};return base64.RawURLEncoding.EncodeToString(b),nil }
func tokenHash(t string) string { h:=sha256.Sum256([]byte(t));return base64.RawStdEncoding.EncodeToString(h[:]) }
func (a *app) health(w http.ResponseWriter,r *http.Request){jsonOut(w,200,map[string]string{"status":"ok"})}
func (a *app) register(w http.ResponseWriter,r *http.Request){
	var in struct { Email, FirstName, LastName, Password, ConfirmPassword, ActorType string };if err:=decode(r,&in);err!=nil {fail(w,400,"Solicitud inválida");return}
	in.Email=strings.ToLower(strings.TrimSpace(in.Email));in.FirstName=strings.TrimSpace(in.FirstName);in.LastName=strings.TrimSpace(in.LastName)
	if !strings.Contains(in.Email,"@")||in.FirstName==""||in.LastName==""||!validPassword(in.Password)||in.Password!=in.ConfirmPassword {fail(w,400,"Revisa los campos; la contraseña debe tener al menos 12 caracteres.");return}
	if in.ActorType=="" {in.ActorType="USER"};if in.ActorType!="USER"&&in.ActorType!="INSTRUCTOR"&&in.ActorType!="LEARNER" {fail(w,400,"Tipo de actor inválido");return}
	h,e:=bcrypt.GenerateFromPassword([]byte(in.Password),bcrypt.DefaultCost);if e!=nil {fail(w,500,"No se pudo crear la cuenta");return}
	var u user;e=a.db.QueryRowContext(r.Context(),`INSERT INTO identity.user(email,password_hash,first_name,last_name,actor_type) VALUES($1,$2,$3,$4,$5) RETURNING id,email,first_name,last_name,actor_type`,in.Email,string(h),in.FirstName,in.LastName,in.ActorType).Scan(&u.ID,&u.Email,&u.FirstName,&u.LastName,&u.ActorType)
	if e!=nil {if strings.Contains(e.Error(),"uq_user_email") {fail(w,409,"El correo ya está registrado");return};log.Print(e);fail(w,500,"No se pudo crear la cuenta");return};jsonOut(w,201,map[string]any{"user":u})
}
func (a *app) login(w http.ResponseWriter,r *http.Request){var in struct{Email,Password,DeviceHint string};if decode(r,&in)!=nil {fail(w,400,"Solicitud inválida");return};var u user;var hash string;var locked sql.NullTime;e:=a.db.QueryRowContext(r.Context(),`SELECT id,email,first_name,last_name,actor_type,password_hash,locked_until FROM identity.user WHERE email=$1 AND is_active=true`,strings.ToLower(strings.TrimSpace(in.Email))).Scan(&u.ID,&u.Email,&u.FirstName,&u.LastName,&u.ActorType,&hash,&locked);if e!=nil||locked.Valid&&locked.Time.After(time.Now())||bcrypt.CompareHashAndPassword([]byte(hash),[]byte(in.Password))!=nil {a.db.ExecContext(r.Context(),`UPDATE identity.user SET failed_attempts=failed_attempts+1,locked_until=CASE WHEN failed_attempts+1>=5 THEN now()+interval '15 minutes' ELSE locked_until END WHERE email=$1`,strings.ToLower(strings.TrimSpace(in.Email)));fail(w,401,"Credenciales inválidas");return};a.db.ExecContext(r.Context(),`UPDATE identity.user SET failed_attempts=0,locked_until=NULL,last_login_at=now() WHERE id=$1`,u.ID);a.respondSession(w,r,u,in.DeviceHint)}
func (a *app) respondSession(w http.ResponseWriter,r *http.Request,u user,device string){access,e:=a.access(u.ID);if e!=nil {fail(w,500,"No se pudo iniciar sesión");return};raw,e:=randomToken();if e!=nil {fail(w,500,"No se pudo iniciar sesión");return};_,e=a.db.ExecContext(r.Context(),`INSERT INTO session.refresh_token(user_id,token_hash,device_hint,ip_address) VALUES($1,$2,$3,$4)`,u.ID,tokenHash(raw),device,clientIP(r));if e!=nil {fail(w,500,"No se pudo iniciar sesión");return};jsonOut(w,200,map[string]any{"accessToken":access,"refreshToken":raw,"user":u})}
func (a *app) access(id string)(string,error){return jwt.NewWithClaims(jwt.SigningMethodHS256,claims{UserID:id,RegisteredClaims:jwt.RegisteredClaims{ExpiresAt:jwt.NewNumericDate(time.Now().Add(15*time.Minute)),IssuedAt:jwt.NewNumericDate(time.Now())}}).SignedString(a.secret)}
func (a *app) refresh(w http.ResponseWriter,r *http.Request){var in struct{RefreshToken string};if decode(r,&in)!=nil||in.RefreshToken=="" {fail(w,400,"Solicitud inválida");return};var u user;e:=a.db.QueryRowContext(r.Context(),`SELECT u.id,u.email,u.first_name,u.last_name,u.actor_type FROM session.refresh_token t JOIN identity.user u ON u.id=t.user_id WHERE t.token_hash=$1 AND NOT t.is_revoked AND t.expires_at>now() AND u.is_active`,tokenHash(in.RefreshToken)).Scan(&u.ID,&u.Email,&u.FirstName,&u.LastName,&u.ActorType);if e!=nil {fail(w,401,"Sesión inválida o vencida");return};a.db.ExecContext(r.Context(),`UPDATE session.refresh_token SET is_revoked=true,revoked_at=now() WHERE token_hash=$1`,tokenHash(in.RefreshToken));a.respondSession(w,r,u,"")}
func (a *app) forgot(w http.ResponseWriter,r *http.Request){var in struct{Email string};if decode(r,&in)!=nil {fail(w,400,"Solicitud inválida");return};raw,e:=randomToken();if e!=nil {fail(w,500,"No se pudo procesar la solicitud");return};var id string;e=a.db.QueryRowContext(r.Context(),`SELECT id FROM identity.user WHERE email=$1 AND is_active`,strings.ToLower(strings.TrimSpace(in.Email))).Scan(&id);if e==nil {_,e=a.db.ExecContext(r.Context(),`INSERT INTO session.password_reset_request(user_id,token_hash,ip_address) VALUES($1,$2,$3)`,id,tokenHash(raw),clientIP(r));if e!=nil {fail(w,500,"No se pudo procesar la solicitud");return}};out:=map[string]string{"message":"Si el correo existe, recibirás instrucciones para recuperar tu acceso."};if os.Getenv("APP_ENV")!="production"&&e==nil {out["developmentToken"]=raw};jsonOut(w,200,out)}
func (a *app) reset(w http.ResponseWriter,r *http.Request){var in struct{Token,Password,ConfirmPassword string};if decode(r,&in)!=nil||!validPassword(in.Password)||in.Password!=in.ConfirmPassword {fail(w,400,"Token o contraseña inválidos");return};tx,e:=a.db.BeginTx(r.Context(),nil);if e!=nil {fail(w,500,"No se pudo actualizar la contraseña");return};defer tx.Rollback();var id string;e=tx.QueryRowContext(r.Context(),`SELECT user_id FROM session.password_reset_request WHERE token_hash=$1 AND NOT is_used AND expires_at>now() FOR UPDATE`,tokenHash(in.Token)).Scan(&id);if e!=nil {fail(w,400,"Token inválido o vencido");return};h,_:=bcrypt.GenerateFromPassword([]byte(in.Password),bcrypt.DefaultCost);_,e=tx.ExecContext(r.Context(),`UPDATE identity.user SET password_hash=$1,updated_at=now(),failed_attempts=0,locked_until=NULL WHERE id=$2`,string(h),id);if e==nil {_,e=tx.ExecContext(r.Context(),`UPDATE session.password_reset_request SET is_used=true WHERE token_hash=$1`,tokenHash(in.Token))};if e==nil {_,e=tx.ExecContext(r.Context(),`UPDATE session.refresh_token SET is_revoked=true,revoked_at=now() WHERE user_id=$1 AND NOT is_revoked`,id)};if e!=nil {fail(w,500,"No se pudo actualizar la contraseña");return};if e=tx.Commit();e!=nil {fail(w,500,"No se pudo actualizar la contraseña");return};jsonOut(w,200,map[string]string{"message":"Contraseña actualizada. Inicia sesión nuevamente."})}
func (a *app) auth(next func(http.ResponseWriter,*http.Request,string)) func(http.ResponseWriter,*http.Request) { return func(w http.ResponseWriter,r *http.Request){p:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ");c:=&claims{};t,e:=jwt.ParseWithClaims(p,c,func(t *jwt.Token)(any,error){if t.Method!=jwt.SigningMethodHS256{return nil,errors.New("firma inválida")};return a.secret,nil});if e!=nil||!t.Valid||c.UserID=="" {fail(w,401,"No autorizado");return};next(w,r,c.UserID)} }
func (a *app) me(w http.ResponseWriter,r *http.Request,id string){var u user;e:=a.db.QueryRowContext(r.Context(),`SELECT id,email,first_name,last_name,actor_type FROM identity.user WHERE id=$1`,id).Scan(&u.ID,&u.Email,&u.FirstName,&u.LastName,&u.ActorType);if e!=nil {fail(w,404,"Usuario no encontrado");return};jsonOut(w,200,map[string]any{"user":u})}
func (a *app) changePassword(w http.ResponseWriter,r *http.Request,id string){var in struct{CurrentPassword,Password,ConfirmPassword string};if decode(r,&in)!=nil||!validPassword(in.Password)||in.Password!=in.ConfirmPassword {fail(w,400,"Contraseña inválida");return};var old string;if a.db.QueryRowContext(r.Context(),`SELECT password_hash FROM identity.user WHERE id=$1`,id).Scan(&old)!=nil||bcrypt.CompareHashAndPassword([]byte(old),[]byte(in.CurrentPassword))!=nil {fail(w,401,"La contraseña actual no es correcta");return};h,_:=bcrypt.GenerateFromPassword([]byte(in.Password),bcrypt.DefaultCost);_,e:=a.db.ExecContext(r.Context(),`UPDATE identity.user SET password_hash=$1,updated_at=now() WHERE id=$2`,string(h),id);if e!=nil {fail(w,500,"No se pudo cambiar la contraseña");return};jsonOut(w,200,map[string]string{"message":"Contraseña actualizada"})}
func clientIP(r *http.Request) string { return strings.Split(r.RemoteAddr, ":")[0] }
var _ = fmt.Sprintf
