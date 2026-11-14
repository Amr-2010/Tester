# أيقونات البيان العربي

تم استخدام الشعار المرفق في أيقونات الويب وPWA وWindows وإعداد مصادر Android وiOS.

- Windows: `branding/albayan.ico` مرتبط بإعدادات electron-builder.
- Web/PWA: `public/icon-192.png` و `public/icon-512.png` وfavicon وApple touch icon.
- Android/iOS: ملفات المصدر في `branding/logo-1024.png`. بعد إنشاء مجلدات المنصات بواسطة Capacitor، نفذ `npx @capacitor/assets generate --iconBackgroundColor '#ffffff' --iconBackgroundColorDark '#ffffff'` بعد نسخ الصورة إلى `assets/icon-only.png` أو اتبع تعليمات أداة Capacitor Assets. يجب التحقق من الناتج في Android Studio وXcode.
- ملفات APK/IPA/EXE النهائية لم يتم بناؤها هنا.
