import React, { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Pressable, SafeAreaView, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import * as SecureStore from 'expo-secure-store';

const API = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:8080';
const emptyForm = { email: '', password: '', confirmPassword: '', firstName: '', lastName: '', currentPassword: '', token: '' };

async function call(path, body, token) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(`${API}${path}`, {
      method: path === '/api/me' ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(path === '/api/me' ? {} : { body: JSON.stringify(body) }), signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'No fue posible conectar con el servicio.');
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('La API no respondió. Verifica que el backend Go esté activo en el puerto 8080.');
    throw error;
  } finally { clearTimeout(timeout); }
}

function AppButton({ label, onPress, variant = 'primary', disabled = false }) {
  return <Pressable disabled={disabled} onPress={onPress} style={({ pressed }) => [styles.button, styles[`button_${variant}`], pressed && !disabled && styles.buttonPressed, disabled && styles.buttonDisabled]}>
    <Text style={[styles.buttonText, styles[`buttonText_${variant}`]]}>{label}</Text>
  </Pressable>;
}

function Field({ label, value, onChangeText, secureTextEntry, placeholder, autoComplete, rightAction }) {
  return <View style={styles.fieldWrap}>
    <Text style={styles.label}>{label}</Text>
    <View style={styles.inputRow}>
      <TextInput
        value={value}
        onChangeText={onChangeText}
        secureTextEntry={secureTextEntry}
        autoCapitalize="none"
        autoCorrect={false}
        autoComplete={autoComplete}
        placeholder={placeholder}
        placeholderTextColor="#9AA7C0"
        style={styles.input}
      />
      {rightAction}
    </View>
  </View>;
}

function Header({ screen, onHome }) {
  const subtitle = screen === 'register' ? 'Crea tu acceso a la plataforma' : screen === 'forgot' ? 'Recupera tu acceso de forma segura' : screen === 'reset' ? 'Elige una nueva contraseña segura' : screen === 'change' ? 'Actualiza tus credenciales de acceso' : 'Accede a tu espacio de trabajo';
  return <View style={styles.header}>
    <Pressable onPress={onHome} style={styles.brandRow}>
      <View style={styles.brandMark}><Text style={styles.brandMarkText}>IAM</Text></View>
      <Text style={styles.brand}>IAM Secure</Text>
    </Pressable>
    <View style={styles.headingArea}>
      <Text style={styles.eyebrow}>MÓDULO DE SEGURIDAD</Text>
      <Text style={styles.title}>{screen === 'register' ? 'Crea tu cuenta' : screen === 'forgot' ? 'Recuperar contraseña' : screen === 'reset' ? 'Nueva contraseña' : screen === 'change' ? 'Cambiar contraseña' : 'Bienvenido de nuevo'}</Text>
      <Text style={styles.subtitle}>{subtitle}</Text>
    </View>
  </View>;
}

export default function App() {
  const [screen, setScreen] = useState('login');
  const [form, setForm] = useState(emptyForm);
  const [user, setUser] = useState(null);
  const [busy, setBusy] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const set = key => value => setForm(current => ({ ...current, [key]: value }));
  const passwordToggle = useMemo(() => <Pressable onPress={() => setShowPassword(value => !value)} style={styles.passwordToggle}><Text style={styles.passwordToggleText}>{showPassword ? 'Ocultar' : 'Mostrar'}</Text></Pressable>, [showPassword]);

  useEffect(() => { (async () => {
    try {
      const token = await SecureStore.getItemAsync('accessToken');
      if (token) {
        try { setUser((await call('/api/me', null, token)).user); setScreen('home'); }
        catch { await SecureStore.deleteItemAsync('accessToken'); await SecureStore.deleteItemAsync('refreshToken'); }
      }
    } finally { setBusy(false); }
  })(); }, []);

  const go = next => { setForm(emptyForm); setShowPassword(false); setNotice(null); setScreen(next); };
  async function submit() {
    try {
      setSubmitting(true); setNotice(null);
      if (screen === 'register') {
        await call('/api/auth/register', {
          email: form.email,
          firstName: form.firstName,
          lastName: form.lastName,
          password: form.password,
          confirmPassword: form.confirmPassword,
        });
        go('login');
        setNotice({ type: 'success', text: 'Cuenta creada correctamente. Ya puedes iniciar sesión.' });
      } else if (screen === 'login') {
        const data = await call('/api/auth/login', { email: form.email, password: form.password, deviceHint: 'Expo IAM Secure' });
        await SecureStore.setItemAsync('accessToken', data.accessToken);
        await SecureStore.setItemAsync('refreshToken', data.refreshToken);
        setUser(data.user); setScreen('home'); setForm(emptyForm);
      } else if (screen === 'forgot') {
        const data = await call('/api/auth/forgot-password', { email: form.email });
        if (data.developmentToken) setForm(current => ({ ...current, token: data.developmentToken }));
        setScreen('reset');
        setNotice({ type: 'success', text: data.developmentToken ? 'Solicitud creada. El código de desarrollo fue cargado automáticamente.' : data.message });
      } else if (screen === 'reset') {
        await call('/api/auth/reset-password', { token: form.token, password: form.password, confirmPassword: form.confirmPassword });
        go('login'); setNotice({ type: 'success', text: 'Contraseña actualizada. Inicia sesión con tu nueva clave.' });
      } else if (screen === 'change') {
        const token = await SecureStore.getItemAsync('accessToken');
        await call('/api/auth/change-password', { currentPassword: form.currentPassword, password: form.password, confirmPassword: form.confirmPassword }, token);
        go('home');
      }
    } catch (error) { setNotice({ type: 'error', text: error.message }); }
    finally { setSubmitting(false); }
  }
  async function logout() { await SecureStore.deleteItemAsync('accessToken'); await SecureStore.deleteItemAsync('refreshToken'); setUser(null); go('login'); }

  if (busy) return <SafeAreaView style={styles.loadingScreen}><View style={styles.loadingMark}><Text style={styles.brandMarkText}>IAM</Text></View><ActivityIndicator color="#FFFFFF" size="large" /><Text style={styles.loadingText}>Preparando tu acceso seguro…</Text></SafeAreaView>;

  if (user && screen === 'home') return <SafeAreaView style={styles.app}><View style={styles.orbOne}/><View style={styles.orbTwo}/><ScrollView contentContainerStyle={styles.homeContent}>
    <View style={styles.topBar}><View style={styles.brandRow}><View style={styles.brandMark}><Text style={styles.brandMarkText}>IAM</Text></View><Text style={styles.brandLight}>IAM Secure</Text></View><Pressable onPress={logout} style={styles.logout}><Text style={styles.logoutText}>Cerrar sesión</Text></Pressable></View>
    <View style={styles.welcomeCard}><View style={styles.successBadge}><Text style={styles.successIcon}>✓</Text></View><Text style={styles.eyebrow}>SESIÓN ACTIVA</Text><Text style={styles.homeTitle}>Hola, {user.firstName}</Text><Text style={styles.homeDescription}>Tu identidad fue verificada. Ya tienes acceso seguro al portal IAM.</Text>
      <View style={styles.userLine}><Text style={styles.userIcon}>✦</Text><View><Text style={styles.userName}>{user.firstName} {user.lastName}</Text><Text style={styles.userEmail}>{user.email}</Text></View><View style={styles.rolePill}><Text style={styles.roleText}>{user.actorType}</Text></View></View>
      <View style={styles.divider}/><Text style={styles.securityTitle}>Centro de seguridad</Text><Text style={styles.securityText}>Mantén tus credenciales actualizadas para proteger tu cuenta.</Text><AppButton label="Cambiar contraseña" onPress={() => go('change')} />
    </View>
  </ScrollView></SafeAreaView>;

  const isRegister = screen === 'register'; const isForgot = screen === 'forgot'; const isReset = screen === 'reset'; const isChange = screen === 'change';
  return <SafeAreaView style={styles.app}><View style={styles.orbOne}/><View style={styles.orbTwo}/><ScrollView contentContainerStyle={styles.pageContent} keyboardShouldPersistTaps="handled"><View style={styles.authShell}>
    <Header screen={screen} onHome={() => go('login')} />
    <View style={styles.formArea}>
      {notice && <View style={[styles.notice, notice.type === 'success' ? styles.noticeSuccess : styles.noticeError]}><Text style={[styles.noticeText, notice.type === 'success' ? styles.noticeTextSuccess : styles.noticeTextError]}>{notice.type === 'success' ? '✓  ' : '!  '}{notice.text}</Text></View>}
      {isRegister && <View style={styles.splitFields}><View style={styles.splitLeft}><Field label="Nombres" value={form.firstName} onChangeText={set('firstName')} placeholder="Ej. Valeria" autoComplete="name-given" /></View><View style={styles.splitRight}><Field label="Apellidos" value={form.lastName} onChangeText={set('lastName')} placeholder="Ej. Gómez" autoComplete="name-family" /></View></View>}
      {!isReset && !isChange && <Field label="Correo electrónico" value={form.email} onChangeText={set('email')} placeholder="nombre@correo.com" autoComplete="email" />}
      {isReset && <Field label="Código de recuperación" value={form.token} onChangeText={set('token')} placeholder="Pega aquí tu código" autoComplete="one-time-code" />}
      {isChange && <Field label="Contraseña actual" value={form.currentPassword} onChangeText={set('currentPassword')} placeholder="Tu contraseña actual" secureTextEntry={!showPassword} rightAction={passwordToggle} autoComplete="current-password" />}
      {!isForgot && <>
        <Field label={isReset || isChange || isRegister ? 'Nueva contraseña' : 'Contraseña'} value={form.password} onChangeText={set('password')} placeholder="Mínimo 12 caracteres" secureTextEntry={!showPassword} rightAction={passwordToggle} autoComplete={isLogin(screen) ? 'current-password' : 'new-password'} />
        {(isRegister || isReset || isChange) && <Field label="Confirmar contraseña" value={form.confirmPassword} onChangeText={set('confirmPassword')} placeholder="Repite tu nueva contraseña" secureTextEntry={!showPassword} autoComplete="new-password" />}
      </>}
      {(isRegister || isReset || isChange) && <Text style={styles.helper}>Usa al menos 12 caracteres para una contraseña segura.</Text>}
      <View style={styles.actionSpace}/><AppButton disabled={submitting} label={submitting ? 'Procesando…' : isRegister ? 'Crear cuenta' : isForgot ? 'Enviar instrucciones' : isReset ? 'Guardar nueva contraseña' : isChange ? 'Actualizar contraseña' : 'Iniciar sesión'} onPress={submit} />
      {screen === 'login' && <View style={styles.loginExtras}><Pressable onPress={() => go('forgot')}><Text style={styles.link}>¿Olvidaste tu contraseña?</Text></Pressable><View style={styles.rule}/><Text style={styles.muted}>¿Aún no tienes una cuenta?</Text><Pressable onPress={() => go('register')}><Text style={styles.link}>Crear una cuenta</Text></Pressable></View>}
      {screen !== 'login' && !isChange && <View style={styles.backWrap}><AppButton label="← Volver a iniciar sesión" variant="ghost" onPress={() => go('login')} /></View>}
    </View>
    <Text style={styles.footer}>IAM Secure · Acceso protegido con autenticación segura</Text>
  </View></ScrollView></SafeAreaView>;
}

function isLogin(screen) { return screen === 'login'; }

const styles = StyleSheet.create({
  app:{flex:1,backgroundColor:'#EEF3FF',overflow:'hidden'}, pageContent:{flexGrow:1,justifyContent:'center',alignItems:'center',padding:24}, authShell:{width:'100%',maxWidth:510,backgroundColor:'rgba(255,255,255,0.97)',borderRadius:28,overflow:'hidden',shadowColor:'#26377A',shadowOpacity:0.2,shadowRadius:28,shadowOffset:{width:0,height:15},elevation:12}, header:{paddingHorizontal:34,paddingTop:32,paddingBottom:24,backgroundColor:'#F8FAFF'}, brandRow:{flexDirection:'row',alignItems:'center',gap:9}, brandMark:{width:32,height:32,borderRadius:11,backgroundColor:'#506BF4',alignItems:'center',justifyContent:'center',shadowColor:'#344AD0',shadowOpacity:0.32,shadowRadius:8,shadowOffset:{width:0,height:4},elevation:4}, brandMarkText:{color:'#FFF',fontWeight:'800',fontSize:12,letterSpacing:0.2}, brand:{fontSize:19,fontWeight:'800',color:'#253354'}, brandLight:{fontSize:19,fontWeight:'800',color:'#FFF'}, headingArea:{marginTop:29}, eyebrow:{color:'#6377DC',fontWeight:'800',fontSize:10,letterSpacing:1.35,marginBottom:8}, title:{fontSize:28,lineHeight:34,fontWeight:'800',color:'#192444',letterSpacing:-0.55}, subtitle:{fontSize:14,lineHeight:21,color:'#71809C',marginTop:8}, formArea:{paddingHorizontal:34,paddingTop:25,paddingBottom:22},notice:{borderRadius:11,paddingHorizontal:13,paddingVertical:11,marginBottom:18},noticeSuccess:{backgroundColor:'#EAF8EF',borderWidth:1,borderColor:'#C5EFD4'},noticeError:{backgroundColor:'#FFF0F0',borderWidth:1,borderColor:'#FFD0D0'},noticeText:{fontSize:12,lineHeight:17,fontWeight:'600'},noticeTextSuccess:{color:'#217443'},noticeTextError:{color:'#B33434'},fieldWrap:{marginBottom:17},label:{color:'#34415C',fontSize:12,fontWeight:'700',marginBottom:7},inputRow:{minHeight:50,borderWidth:1,borderColor:'#E0E6F0',backgroundColor:'#FFF',borderRadius:12,flexDirection:'row',alignItems:'center'},input:{flex:1,paddingHorizontal:14,paddingVertical:13,fontSize:14,color:'#273551',outlineStyle:'none'},passwordToggle:{paddingHorizontal:13,paddingVertical:9},passwordToggleText:{fontSize:12,fontWeight:'700',color:'#5269E6'},splitFields:{flexDirection:'row',gap:12},splitLeft:{flex:1},splitRight:{flex:1},helper:{fontSize:11.5,lineHeight:17,color:'#8390A8',marginTop:-5},actionSpace:{height:9},button:{height:51,borderRadius:12,alignItems:'center',justifyContent:'center',paddingHorizontal:18},button_primary:{backgroundColor:'#5269E8',shadowColor:'#5269E8',shadowOpacity:0.3,shadowRadius:10,shadowOffset:{width:0,height:5},elevation:5},button_ghost:{backgroundColor:'transparent',height:42},buttonText:{fontSize:14,fontWeight:'800'},buttonText_primary:{color:'#FFF'},buttonText_ghost:{color:'#6073D9'},buttonPressed:{opacity:0.83,transform:[{scale:0.99}]},buttonDisabled:{opacity:0.55},loginExtras:{alignItems:'center',paddingTop:21},link:{color:'#5169E8',fontSize:12,fontWeight:'800',paddingVertical:8},rule:{height:1,backgroundColor:'#EEF1F6',alignSelf:'stretch',marginVertical:7},muted:{color:'#8B97AD',fontSize:12},backWrap:{marginTop:14},footer:{textAlign:'center',fontSize:10.5,color:'#8C98AF',paddingHorizontal:22,paddingBottom:23},orbOne:{position:'absolute',width:420,height:420,borderRadius:210,backgroundColor:'#C9D8FF',top:-195,left:-140,opacity:0.67},orbTwo:{position:'absolute',width:410,height:410,borderRadius:205,backgroundColor:'#E1C9FF',bottom:-250,right:-170,opacity:0.6},loadingScreen:{flex:1,backgroundColor:'#536AE8',alignItems:'center',justifyContent:'center',gap:18},loadingMark:{width:58,height:58,borderWidth:1,borderColor:'rgba(255,255,255,0.36)',borderRadius:18,alignItems:'center',justifyContent:'center'},loadingText:{fontSize:14,color:'rgba(255,255,255,0.85)',fontWeight:'600'},homeContent:{flexGrow:1,padding:24,justifyContent:'center',alignItems:'center'},topBar:{width:'100%',maxWidth:760,position:'absolute',top:28,flexDirection:'row',justifyContent:'space-between',alignItems:'center'},logout:{paddingHorizontal:15,paddingVertical:9,borderRadius:10,borderWidth:1,borderColor:'rgba(255,255,255,0.38)'},logoutText:{color:'#FFF',fontWeight:'700',fontSize:12},welcomeCard:{width:'100%',maxWidth:580,backgroundColor:'rgba(255,255,255,0.97)',borderRadius:28,padding:35,alignItems:'center',shadowColor:'#26377A',shadowOpacity:0.2,shadowRadius:28,shadowOffset:{width:0,height:15},elevation:12},successBadge:{width:55,height:55,borderRadius:18,backgroundColor:'#E8F8EF',alignItems:'center',justifyContent:'center',marginBottom:19},successIcon:{color:'#28A764',fontSize:28,fontWeight:'700'},homeTitle:{fontSize:30,fontWeight:'800',color:'#1A2745',letterSpacing:-0.7},homeDescription:{fontSize:14,lineHeight:21,color:'#71809C',textAlign:'center',marginTop:10,maxWidth:360},userLine:{marginTop:27,width:'100%',backgroundColor:'#F6F8FE',padding:16,borderRadius:15,flexDirection:'row',alignItems:'center',gap:11},userIcon:{fontSize:19,color:'#5169E8'},userName:{fontSize:13,fontWeight:'800',color:'#33425E'},userEmail:{fontSize:11.5,color:'#7A89A3',marginTop:3},rolePill:{marginLeft:'auto',backgroundColor:'#E3E9FF',paddingHorizontal:9,paddingVertical:5,borderRadius:8},roleText:{fontSize:9,fontWeight:'800',color:'#5369D7'},divider:{height:1,backgroundColor:'#EDF0F5',alignSelf:'stretch',marginVertical:24},securityTitle:{alignSelf:'flex-start',fontSize:15,fontWeight:'800',color:'#33425E'},securityText:{alignSelf:'flex-start',fontSize:12.5,lineHeight:19,color:'#7B88A1',marginTop:6,marginBottom:17},
});
