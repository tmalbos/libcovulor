from .database import findings_collection
from bson.objectid import ObjectId
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

class Finding:
    ACCESS_CREDENTIAL = 'access_credential'
    ACTUAL_LINE = 'line'
    ASVS_ID = 'asvs_id'
    ASVS_SECTION = 'asvs_section'
    CLIENT_ID = 'client_id'
    CONFIDENCE = 'confidence'
    CVSSV3_SCORE = 'cvssv3_score'
    CVSSV3_VECTOR = 'cvssv3_vector'
    CWES = 'cwe'
    DATA_SOURCE = 'data_source'
    DATE = 'date'
    DESCRIPTION = 'description'
    DUPLICATE_ID = 'duplicate_finding_id'
    EPSS = 'estimated_epss'
    EXCLUDED_FILE_TYPES = 'excluded_file_types'
    FILE = 'file_path'
    FIXING_EFFORT = 'effort_for_fixing'
    ID = 'uri'
    IMPACT = 'impact'
    IS_DUPLICATE = 'duplicate'
    IS_FALSE_POSITIVE = 'is_false_positive'
    IS_MITIGATED_EXTERNALLY = 'is_mitigated_externally'
    ISSUE_OWNER = 'issue_owner'
    LIKELIHOOD = 'likelihood'
    MITIGATION = 'mitigation'
    NOTES = 'notes'
    NUMERICAL_SEVERITY = 'severity_numerical'
    ORIGINAL_LINE = 'original_line'
    OWASPS = 'owasps'
    PLATFORM = 'platform'
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
    SLSA_THREATS = 'slsa_threats'
    STATUS = 'status'
    SUPPLY_CHAINS = 'supply_chains'
    TAGS = 'tags'
    TARGET_FILE_TYPES = 'target_file_types'
    TITLE = 'title'
    TOOL = 'tool'
    TYPE = 'vuln_type'

    @staticmethod
    def create(data: dict):
        try:
            existing_document = findings_collection.find_one({
                    Finding.CWES: data[Finding.CWES],
                    Finding.FILE: data[Finding.FILE],
                    Finding.ORIGINAL_LINE: data[Finding.ORIGINAL_LINE],
                    Finding.TOOL: data[Finding.TOOL]
            })

            if existing_document:
                actual_title = data[Finding.TITLE]
                data.update(existing_document)
                data[Finding.TITLE] = actual_title
                data[Finding.IS_DUPLICATE] = True
                data[Finding.DUPLICATE_ID] = str(existing_document["_id"])
                del data["_id"]

            data[Finding.PROCESSING_STATUS] = "processing"
            finding = findings_collection.insert_one(data)

            return {"id": str(finding.inserted_id), Finding.IS_DUPLICATE: data[Finding.IS_DUPLICATE]} if finding.inserted_id else None
        except PyMongoError as e:
            print(f'Error: {e}')

            return None

class FindingModel(BaseModel):
    _id: ObjectId = Field(exclude=True, alias='_id')
    access_credential: str = Field(default=None, alias=Finding.ACCESS_CREDENTIAL)
    actual_line: int = Field(ge=1, alias=Finding.ACTUAL_LINE)
    asvs_id: str = Field(default=None, alias=Finding.ASVS_ID)
    asvs_section: str = Field(default=None, alias=Finding.ASVS_SECTION)
    client_id: str = Field(alias=Finding.CLIENT_ID)
    confidence: int = Field(default=100, ge=0, le=100, alias=Finding.CONFIDENCE)
    cvssv3_score: float = Field(default=0.0, ge=0.0, alias=Finding.CVSSV3_SCORE)
    cvssv3_vector: list = Field(default=[], alias=Finding.CVSSV3_VECTOR)
    cwes: list = Field(default=[], alias=Finding.CWES)
    data_source: str = Field(default=None, alias=Finding.DATA_SOURCE)
    date: str = Field(pattern=r'\d{4}-\d{2}-\d{2}', alias=Finding.DATE)
    description: str = Field(alias=Finding.DESCRIPTION)
    duplicate_id: str = Field(default=None, alias=Finding.DUPLICATE_ID)
    epss: int = Field(default=0, alias=Finding.EPSS)
    excluded_file_types: list = Field(default=[], alias=Finding.EXCLUDED_FILE_TYPES)
    file: str = Field(alias=Finding.FILE)
    fixing_effort: str = Field(default=None, alias=Finding.FIXING_EFFORT)
    id: str = Field(alias=Finding.ID)
    impact: str = Field(default=None, alias=Finding.IMPACT)
    is_duplicate: bool = Field(default=False, alias=Finding.IS_DUPLICATE)
    is_false_positive: bool = Field(default=False, alias=Finding.IS_FALSE_POSITIVE)
    is_mitigated_externally: bool = Field(default=False, alias=Finding.IS_MITIGATED_EXTERNALLY)
    issue_owner: str = Field(default=None, alias=Finding.ISSUE_OWNER)
    likelihood: str = Field(default=None, alias=Finding.LIKELIHOOD)
    mitigation: str = Field(default=None, alias=Finding.MITIGATION)
    notes: list = Field(default=[], alias=Finding.NOTES)
    numerical_severity: int = Field(default=0, ge=0, le=100, alias=Finding.NUMERICAL_SEVERITY)
    original_line: int = Field(ge=1, alias=Finding.ORIGINAL_LINE)
    owasps: list = Field(default=[], alias=Finding.OWASPS)
    platform: str = Field(default=None, alias=Finding.PLATFORM)
    priority: int = Field(default=0, ge=0, le=100, alias=Finding.PRIORITY)
    processing_status: str = Field(default='processing', alias=Finding.PROCESSING_STATUS)
    provider: str = Field(default=None, alias=Finding.PROVIDER)
    record_source: str = Field(default=None, alias=Finding.RECORD_SOURCE)
    references: list = Field(default=[], alias=Finding.REFERENCES)
    remediation_type: str = Field(default=None, alias=Finding.REMEDIATION_TYPE)
    repository_id: str = Field(default=None, alias=Finding.REPOSITORY_ID)
    resource_entity: str = Field(default=None, alias=Finding.RESOURCE_ENTITY)
    review_requested_by: str = Field(default=None, alias=Finding.REVIEW_REQUESTED_BY)
    sast_sink_object: str = Field(default=None, alias=Finding.SAST_SINK_OBJECT)
    sast_source_file: str = Field(default=None, alias=Finding.SAST_SOURCE_FILE)
    sast_source_line: str = Field(default=None, alias=Finding.SAST_SOURCE_LINE)
    sast_source_object: str = Field(default=None, alias=Finding.SAST_SOURCE_OBJECT)
    scan_id: str = Field(default=None, alias=Finding.SCAN_ID)
    scanner_report: str = Field(default=None, alias=Finding.SCANNER_REPORT)
    scanner_report_code: str = Field(default=None, alias=Finding.SCANNER_REPORT_CODE)
    scanner_weakness: str = Field(default=None, alias=Finding.SCANNER_WEAKNESS)
    service: str = Field(default=None, alias=Finding.SERVICE)
    severity: str = Field(default=None, alias=Finding.SEVERITY)
    slsa_threats: list = Field(default=[], alias=Finding.SLSA_THREATS)
    status: str = Field(default='In Progress', alias=Finding.STATUS)
    supply_chains: list = Field(default=[], alias=Finding.SUPPLY_CHAINS)
    tags: list = Field(default=[], alias=Finding.TAGS)
    target_file_types: list = Field(default=[], alias=Finding.TARGET_FILE_TYPES)
    title: str = Field(default=None, alias=Finding.TITLE)
    tool: str = Field(default=None, alias=Finding.TOOL)
    type: str = Field(default='Code Weakness', alias=Finding.TYPE)
