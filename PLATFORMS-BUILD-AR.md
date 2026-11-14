# دليل بناء Windows / Android / iOS — البيان العربي

هذا المشروع يحتوي على **مصدر أغلفة التطبيقات وأوامر إنشائها**، وليس ملفات APK/EXE/IPA جاهزة. يجب تشغيل البناء على أنظمة التطوير المناسبة.

## قبل البناء
1. انشر الخادم وقاعدة PostgreSQL على Render واختبر الرابط عبر HTTPS.
2. استبدل `https://YOUR-SERVICE.onrender.com` برابطك الحقيقي في `desktop/config.json` و `capacitor.config.json`.
3. نفذ `npm install` داخل مجلد `AlBayan-SecureSuite`.
4. لا تضع DATABASE_URL أو أسرار الخادم داخل التطبيقات؛ الاتصال يتم عبر HTTPS فقط.

## Windows EXE
على Windows مع Node.js: `npm run build:windows`؛ يظهر ملف التثبيت عادةً في `dist/`. التطبيق يفتح واجهة Render، ولا يشغل PostgreSQL محليًا.

## Android APK
ثبّت Android Studio وJava SDK، ثم نفّذ `npm run android:add` (مرة واحدة) و`npm run android:sync` و`npm run android:open`. من Android Studio اختر Build APK(s) أو Generate Signed Bundle/APK. سيُنشأ مجلد `android/` عند تشغيل add، وليس داخل هذه الحزمة.

## iOS
يلزم جهاز macOS مع Xcode وApple signing. نفّذ `npm run ios:add` (مرة واحدة)، ثم `npm run ios:sync` و`npm run ios:open`، ومن Xcode ابنِ التطبيق ووقّعه. سيُنشأ مجلد `ios/` عند تشغيل add على macOS.

## حدود النسخة
الأغلفة تعرض تطبيق الويب المنشور، ولا تضيف وحدها تشغيل اختبارات APK/EXE تلقائيًا أو مراقبة بث صوت/فيديو بالذكاء الاصطناعي. تلك الوظائف تحتاج runners وخدمات تحليل منفصلة. لم يتم بناء أو اختبار ملفات التثبيت في هذه البيئة.
