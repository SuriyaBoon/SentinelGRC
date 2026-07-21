# SentinelGRC

SentinelGRC คือ security governance platform สำหรับเปลี่ยน security observation หรือ alert ให้กลายเป็น workflow ที่ตรวจสอบย้อนหลังได้ ตั้งแต่การสร้าง finding ไปจนถึงการปิดประเด็นอย่างมีหลักฐาน

โปรเจกต์นี้เป็น portfolio lab และ concept validation ไม่ใช่ระบบ production สำเร็จรูป และไม่อ้างว่าได้รับการรับรอง ISO หรือพร้อมใช้งานระดับองค์กรโดยไม่ต้องทำ production hardening เพิ่มเติม

## 1. SentinelGRC คืออะไร

SentinelGRC แก้ปัญหาการทำงานด้าน security ที่มักแยกอยู่หลายที่ เช่น alert อยู่ใน log tool, risk อยู่ใน spreadsheet, approval อยู่ใน chat และ evidence อยู่ในโฟลเดอร์ส่วนตัว

ระบบรวมข้อมูลเหล่านี้ให้มี identity และ lifecycle เดียวกัน:

```text
Security observation / alert
        ↓
Finding
        ↓
Risk assessment
        ↓
Treatment proposal
        ↓
Role-gated approval
        ↓
Remediation action
        ↓
Evidence submission
        ↓
Independent verification
        ↓
Closure
```

จุดประสงค์หลักคือทำให้ตอบได้:

- พบปัญหาอะไร และเกิดกับ asset ใด
- ใครเป็นผู้รับผิดชอบและใครมีสิทธิ์อนุมัติ
- ความเสี่ยงถูกประเมินและจัดการอย่างไร
- มีหลักฐานอะไรยืนยันการแก้ไข
- ผู้ตรวจสอบเป็นคนอื่นจากผู้ลงมือแก้หรือไม่
- finding เดิมถูกสร้างซ้ำจากการ replay หรือไม่
- รายการที่ปิดแล้วตรวจสอบย้อนหลังได้หรือไม่

## 2. ระบบทำงานอย่างไร

### Security ingestion

ระบบรับข้อมูลจาก security control, posture collector, access review และ alert connector โดยตรวจสอบรูปแบบข้อมูลและ identity ของ machine agent ก่อนนำเข้าสู่ pipeline

### Finding และ risk

ข้อมูลที่ผ่านการตรวจสอบจะถูกผูกกับ asset และ control จากนั้นสร้างหรือ reassess finding เดิมด้วย stable identity เพื่อป้องกัน open finding ซ้ำ

### Governance workflow

finding จะไหลผ่าน state machine ที่บังคับลำดับการทำงานและ role ที่เกี่ยวข้อง การอนุมัติและการปิดรายการใช้ actor จาก server-side context ไม่รับตัวตนสำคัญจาก request body โดยตรง

### Evidence และ audit

การเปลี่ยนสถานะ การอนุมัติ การส่ง evidence และการตรวจสอบจะถูกบันทึกใน relational governance store พร้อม hash metadata และ audit chain เพื่อช่วยตรวจจับการแก้ไขย้อนหลัง

### Concept integration

การทดสอบที่ทำจริงใน repository นี้ใช้ LogWatcher เป็นแหล่งข้อมูลตัวอย่าง:

```text
20 Windows-style events
        ↓
LogWatcher detection
        ↓
3 alerts
        ↓
SentinelGRC staging connector
        ↓
3 findings
        ↓ replay เดิมอีกครั้ง
0 findings ใหม่ + 3 reassessments
```

การทดสอบนี้พิสูจน์ alert ingestion และ idempotency ของ finding workflow ในระดับ concept ไม่ใช่การพิสูจน์ live Windows fleet, Elastic cluster หรือ enterprise deployment จริง

## 3. คำสั่งที่ใช้

### ตรวจชุดทดสอบ

ใช้ Python 3 และรันจาก root ของ repository:

```powershell
python -m compileall -q .
python -m unittest discover -q
```

### รัน SentinelGRC staging connector

เตรียมไฟล์ alert จาก LogWatcher แล้วรัน:

```powershell
python -m scripts.staging_logwatcher `
  --events ..\LogWatcher\runtime\alerts.jsonl `
  --input-kind alert `
  --governance-db runtime\concept-governance.db
```

รันคำสั่งเดิมซ้ำอีกครั้งเพื่อทดสอบ replay และ deduplication

### รัน pipeline แบบ governance storage

```powershell
python -m scripts.pipeline run `
  --posture sample_posture.json `
  --access-review sample_ad_access_review.json `
  --governance-db runtime\governance.db
```

คำสั่งและ scenario เพิ่มเติมอยู่ใน [docs/staging-logwatcher-validation.md](docs/staging-logwatcher-validation.md) และ [docs/phase1-production-mvp.md](docs/phase1-production-mvp.md)

## 4. หลักฐานการทำงานที่พิสูจน์ว่าใช้ได้

หลักฐาน concept validation อยู่ใน [docs/evidence/concept-validation/](docs/evidence/concept-validation/)

| หลักฐาน | สิ่งที่พิสูจน์ |
|---|---|
| `report.json` | LogWatcher ประมวลผล event ตัวอย่าง 20 รายการ |
| `alerts.jsonl` | ตรวจพบ alert ที่มีโครงสร้าง 3 รายการ |
| `01-logwatcher-report.png` | ผลการตรวจจับจาก terminal |
| `02-sentinel-replay.png` | ผลการ ingest รอบแรกและ replay รอบที่สอง |
| `SHA256SUMS.txt` | checksum ของ evidence ที่เก็บไว้ |
| `python -m unittest discover -q` | automated tests ผ่าน 85 tests |
| GitHub Actions | ตรวจ compile และ test บน CI ของ repository |

ผลลัพธ์ที่คาดหวังจาก SentinelGRC:

```text
รอบแรก: events_read=3, findings_created=3, errors=0
รอบสอง: events_read=3, findings_created=0,
         findings_reassessed=3, errors=0
```

ผลลัพธ์นี้ยืนยันว่า alert ถูกอ่านได้, finding ถูกสร้างได้, replay ไม่สร้าง duplicate finding และระบบ reassess finding เดิมได้

## 5. SentinelGRC แก้ปัญหาอะไร

### Alert ไม่มี owner และ workflow ที่ชัดเจน

ระบบเปลี่ยน alert ให้เป็น finding ที่มี asset, control, risk และ action เชื่อมโยงกัน

### Finding ซ้ำเมื่อ event ถูกส่งซ้ำ

ระบบใช้ stable finding identity และ idempotent upsert เพื่อให้ replay กลายเป็น reassessment แทนการสร้างรายการใหม่

### Approval และ closure ปลอมแปลงได้จาก caller

ระบบใช้ authenticated/server-derived actor และ role-gated transition ไม่เปิดให้ request body เลือก approver หรือ closer เอง

### คนแก้เป็นคนตรวจงานตัวเอง

มี separation-of-duties rule ที่ป้องกัน implementer หรือ evidence submitter จากการ verify งานของตัวเอง

### Audit และ evidence กระจัดกระจาย

ระบบเก็บ workflow record, audit event และ evidence metadata ในรูปแบบที่เชื่อมโยงกัน พร้อม hash-chain/checksum สำหรับตรวจจับความผิดปกติ

## ขอบเขตปัจจุบันและสิ่งที่ยังไม่ใช่

ปัจจุบันรองรับ security governance workflow และ LogWatcher alert-level concept integration บน local/lab environment

ยังไม่ควรอ้างว่าเป็น production-ready enterprise platform เพราะการใช้งานจริงยังต้องเพิ่ม:

- PostgreSQL หรือ shared transactional database
- OIDC/SSO, MFA และ short-lived token
- encrypted object storage และ immutable/WORM archive
- durable queue, secret manager, TLS/WAF และ rate limiting
- backup/restore, monitoring, tracing และ security assessment
- connector จริงสำหรับ Windows fleet, Elastic/SIEM และ ITSM

## โครงสร้าง repository

```text
scripts/      CLI entrypoints และ operational runners
docs/         architecture, deployment และ validation evidence
runtime/      local runtime state; ไม่ควร commit ขึ้น Git
ui/           governance UI shell
tests         test modules ที่ยังอยู่ root เพื่อรองรับ unittest discovery ปัจจุบัน
```

Core modules ยังอยู่ root เพื่อรักษา import compatibility ของ Phase 1 ส่วนคำสั่ง operational ใช้รูปแบบ `python -m scripts.<name>`

## สถานะ

SentinelGRC Phase 1 เป็น authenticated, relational, risk-to-evidence governance workflow ที่ผ่าน automated tests และ concept validation แล้ว แต่ production infrastructure และ enterprise integrations ยังเป็นขั้นตอนถัดไป
