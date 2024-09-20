from .database import Database, MongoDBClient
from datetime import datetime
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError
from typing import Optional

class Finding:
    ACCESS_CREDENTIAL = 'access_credential'
    ACTUAL_LINE = 'line'
    AGGREGATED = 'aggregated'
    ASVS_ID = 'asvs_id'
    ASVS_SECTION = 'asvs_section'
    CATEGORY = 'category'
    CLIENT_ID = 'client_id'
    CONFIDENCE = 'confidence'
    CVE = 'cve'
    CVSSV3_SCORE = 'cvssv3_score'
    CVSSV3_VECTOR = 'cvssv3_vector'
    CWE = 'cwe'
    DATA_SOURCE = 'data_source'
    DATE = 'date'
    DESCRIPTION = 'description'
    DEVELOPER_IDS = 'developer_ids'
    DUPLICATE_ID = 'duplicate_finding_id'
    END_COLUMN = 'end_column'
    EPSS = 'estimated_epss'
    EXCLUDED_FILE_TYPES = 'excluded_file_types'
    EXPLOITABILITY = 'exploitability'
    EXTRA_CWE = 'extra_cwe'
    FALSE_POSITIVE_TYPE = 'fp_type'
    FILE = 'file_path'
    FIXING_EFFORT = 'effort_for_fixing'
    ID = 'finding_id'
    IMPACT = 'impact'
    IS_DUPLICATE = 'duplicate'
    IS_FALSE_POSITIVE = 'is_false_positive'
    IS_MITIGATED_EXTERNALLY = 'is_mitigated_externally'
    ISSUE_OWNER = 'issue_owner'
    LANGUAGE = 'language'
    LIKELIHOOD = 'likelihood'
    MITIGATION = 'mitigation'
    NB_OCCURRENCES = 'nb_occurrences'
    NOTES = 'notes'
    NUMERICAL_SEVERITY = 'severity_numerical'
    ORIGINAL_LINE = 'original_line'
    OWASPS = 'owasps'
    PLATFORM = 'platform'
    POLICY_CONTROL = 'policy_control'
    POLICY_DESCRIPTION = 'policy_description'
    POLICY_NAME = 'policy_name'
    POLICY_RULES = 'policy_rules'
    PRIORITY = 'prioritization_value'
    PROCESSING_STATUS = 'processing_status'
    PROVIDER = 'provider'
    RECORD_SOURCE = 'record_source'
    REFERENCES = 'references'
    REMEDIATION_TYPE = 'remediation_type'
    REPOSITORY_ID = 'repo_id'
    RESOURCE_ENTITY = 'resource_entity'
    REVIEW_REQUESTED_BY = 'review_requested_by_id'
    SAST_SINK_OBJECT = 'sast_sink_object'
    SAST_SOURCE_FILE = 'sast_source_file_path'
    SAST_SOURCE_LINE = 'sast_source_line'
    SAST_SOURCE_OBJECT = 'sast_source_object'
    SCAN_ID = 'scan_id'
    SCANNER_REPORT = 'scanner_report'
    SCANNER_REPORT_CODE = 'scanner_report_code'
    SCANNER_WEAKNESS = 'scanner_weakness'
    SERVICE = 'service'
    SEVERITY = 'severity'
    SINGLE_LINE_CODE = 'single_line_code'
    SLSA_THREATS = 'slsa_threats'
    START_COLUMN = 'start_column'
    STATUS = 'status'
    TAGS = 'tags'
    TARGET_FILE_TYPES = 'target_file_types'
    TITLE = 'title'
    TOOL = 'tool'
    TYPE = 'type'
    WASC = 'wasc'

    STATUS_NEW = 'new'
    STATUS_ENRICHED = 'enriched'
    STATUS_READY = 'ready'
    STATUS_SOLVED = 'solved'
    STATUS_ISSUED = 'issued'

    def __init__(self, database_username=None, database_password=None, database_host="mongodb", port: int = 27017, database_options=None, db_name="plexicus"):
        self.db = Database(database_username, database_password, database_host, port, database_options, db_name)
        self.db_username = database_username
        self.db_password = database_password
        self.db_host = database_host
        self.db_port = port
        self.db_options = database_options
        self.db_name = db_name

    async def create(self, data: dict):
        data[Finding.PROCESSING_STATUS] = "processing"
        finding_model = FindingModel.parse_obj(data)
        finding = await self.db.insert_one(self.db.findings_collection, finding_model.model_dump(by_alias=True))

        if not finding:
            return None

        finding_model.object_id = finding

        return finding_model

    async def delete(self, client_id: str, finding_id: str):
        dict_finding = await self.db.delete_one(self.db.findings_collection, client_id, finding_id)

        return FindingModel.parse_obj(dict_finding)

    async def delete_many(self, client_id: str, options: dict = None):
        dict_finding = await self.db.delete_many(self.db.findings_collection, client_id, options)

        return dict_finding

    async def find_many(self, client_id: str, options: dict = None):
        findings = await self.db.find_many(self.db.findings_collection, client_id, options)
        model_data = []

        for finding in findings['data']:
            model_finding = FindingModel.parse_obj(finding)
            model_data.append(model_finding)

        findings['data'] = model_data

        return findings

    async def find_one(self, client_id: str, finding_id: str):
        dict_finding = await self.db.find_one(self.db.findings_collection, client_id, finding_id)

        return FindingModel.parse_obj(dict_finding)

    async def update(self, client_id: str, finding_id: str, data: dict):
        dict_finding = await self.db.update_one(self.db.findings_collection, client_id, finding_id, data)

        return FindingModel.parse_obj(dict_finding)

class FindingModel(BaseModel):
    object_id: Optional[str] = Field(default=None, exclude=True, alias='_id')
    access_credential: bool = Field(default=False, alias=Finding.ACCESS_CREDENTIAL)
    actual_line: int = Field(ge=0, alias=Finding.ACTUAL_LINE)
    aggregated: bool = Field(default=False, alias=Finding.AGGREGATED)
    asvs_id: Optional[str] = Field(default=None, alias=Finding.ASVS_ID)
    asvs_section: Optional[str] = Field(default=None, alias=Finding.ASVS_SECTION)
    category: str = Field(default='Code Security', alias=Finding.CATEGORY)
    client_id: str = Field(alias=Finding.CLIENT_ID)
    confidence: int = Field(default=50, ge=0, le=100, alias=Finding.CONFIDENCE)
    cve: Optional[str] = Field(default=None, alias=Finding.CVE)
    cvssv3_score: float = Field(default=0.0, ge=0.0, alias=Finding.CVSSV3_SCORE)
    cvssv3_vector: list = Field(default=[], alias=Finding.CVSSV3_VECTOR)
    cwe: Optional[int] = Field(default=None, alias=Finding.CWE)
    data_source: Optional[str] = Field(default=None, alias=Finding.DATA_SOURCE)
    date: datetime = Field(alias=Finding.DATE)
    description: str = Field(alias=Finding.DESCRIPTION)
    developer_ids: list = Field(default=[], alias=Finding.DEVELOPER_IDS)
    duplicate_id: Optional[str] = Field(default=None, alias=Finding.DUPLICATE_ID)
    end_column: Optional[int] = Field(default=1, ge=0, alias=Finding.END_COLUMN)
    epss: float = Field(default=0, alias=Finding.EPSS)
    excluded_file_types: list = Field(default=[], alias=Finding.EXCLUDED_FILE_TYPES)
    exploitability: Optional[str] = Field(default=None, alias=Finding.EXPLOITABILITY)
    extra_cwe: Optional[list] = Field(default=[], alias=Finding.EXTRA_CWE)
    false_positive_type: Optional[str] = Field(default=None, alias=Finding.FALSE_POSITIVE_TYPE)
    file: str = Field(alias=Finding.FILE)
    fixing_effort: Optional[str] = Field(default=None, alias=Finding.FIXING_EFFORT)
    id: str = Field(alias=Finding.ID)
    impact: Optional[str] = Field(default=None, alias=Finding.IMPACT)
    is_duplicate: bool = Field(default=False, alias=Finding.IS_DUPLICATE)
    is_false_positive: bool = Field(default=False, alias=Finding.IS_FALSE_POSITIVE)
    is_mitigated_externally: bool = Field(default=False, alias=Finding.IS_MITIGATED_EXTERNALLY)
    issue_owner: Optional[str] = Field(default=None, alias=Finding.ISSUE_OWNER)
    language: Optional[str] = Field(default=None, alias=Finding.LANGUAGE)
    likelihood: Optional[str] = Field(default=None, alias=Finding.LIKELIHOOD)
    mitigation: Optional[str] = Field(default=None, alias=Finding.MITIGATION)
    nb_occurrences: Optional[int] = Field(default=None, alias=Finding.NB_OCCURRENCES)
    notes: list = Field(default=[], alias=Finding.NOTES)
    numerical_severity: int = Field(default=0, ge=0, le=100, alias=Finding.NUMERICAL_SEVERITY)
    original_line: int = Field(ge=0, alias=Finding.ORIGINAL_LINE)
    owasps: list = Field(default=[], alias=Finding.OWASPS)
    platform: Optional[str] = Field(default=None, alias=Finding.PLATFORM)
    policy_rules: list = Field(default=[], alias=Finding.POLICY_RULES)
    priority: int = Field(default=0, ge=0, le=100, alias=Finding.PRIORITY)
    processing_status: str = Field(default='processing', alias=Finding.PROCESSING_STATUS)
    provider: Optional[str] = Field(default=None, alias=Finding.PROVIDER)
    record_source: Optional[str] = Field(default=None, alias=Finding.RECORD_SOURCE)
    references: list = Field(default=[], alias=Finding.REFERENCES)
    remediation_type: Optional[str] = Field(default=None, alias=Finding.REMEDIATION_TYPE)
    repository_id: str = Field(alias=Finding.REPOSITORY_ID)
    resource_entity: Optional[str] = Field(default=None, alias=Finding.RESOURCE_ENTITY)
    review_requested_by: Optional[str] = Field(default=None, alias=Finding.REVIEW_REQUESTED_BY)
    sast_sink_object: Optional[str] = Field(default=None, alias=Finding.SAST_SINK_OBJECT)
    sast_source_file: Optional[str] = Field(default=None, alias=Finding.SAST_SOURCE_FILE)
    sast_source_line: Optional[str] = Field(default=None, alias=Finding.SAST_SOURCE_LINE)
    sast_source_object: Optional[str] = Field(default=None, alias=Finding.SAST_SOURCE_OBJECT)
    scan_id: Optional[str] = Field(default=None, alias=Finding.SCAN_ID)
    scanner_report: Optional[str] = Field(default=None, alias=Finding.SCANNER_REPORT)
    scanner_report_code: Optional[str] = Field(default=None, alias=Finding.SCANNER_REPORT_CODE)
    scanner_weakness: Optional[str] = Field(default=None, alias=Finding.SCANNER_WEAKNESS)
    service: Optional[str] = Field(default=None, alias=Finding.SERVICE)
    severity: str = Field(alias=Finding.SEVERITY)
    single_line_code: Optional[str] = Field(default=None, alias=Finding.SINGLE_LINE_CODE)
    slsa_threats: list = Field(default=[], alias=Finding.SLSA_THREATS)
    start_column: Optional[int] = Field(default=1, ge=0, alias=Finding.START_COLUMN)
    status: str = Field(default=Finding.STATUS_NEW, alias=Finding.STATUS)
    tags: list = Field(default=[], alias=Finding.TAGS)
    target_file_types: list = Field(default=[], alias=Finding.TARGET_FILE_TYPES)
    title: str = Field(alias=Finding.TITLE)
    tool: str = Field(alias=Finding.TOOL)
    type: str = Field(default='SAST', alias=Finding.TYPE)
    wasc: Optional[str] = Field(default=None, alias=Finding.WASC)

    class Config:
        arbitrary_types_allowed = True
