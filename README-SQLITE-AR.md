# Tester — ASP.NET Core + SQLite (نسخة تجريبية)

- قاعدة SQLite: `Data/tester.db` داخل الحاوية؛ غير دائمة على Render المجاني.
- Dockerfile يستخدم .NET 8 ولا يشغّل Node.js.
- أضف في Render: `JWT_SECRET` (32 حرفًا عشوائيًا على الأقل)، `ADMIN_USER`، `ADMIN_PASSWORD` (12 حرفًا على الأقل).
- لا تضف `DATABASE_URL`، ولا تربط قاعدة Xerox.
- افتح `/api/health` للتحقق من الاتصال.
- حساب المسؤول الأول ينشأ تلقائيًا عند بدء التشغيل بقاعدة فارغة.
- المستخدم العميل لا يرى إلا تقارير `client_id` الخاص به عبر `/api/client/reports`.
- الاختبارات الآلية الحقيقية وAI وتصدير PDF/Excel/PowerPoint غير مكتملة.
- هذا المصدر لم يُبنَ بـ dotnet في بيئة العمل الحالية، ويحتاج CI للتحقق.
