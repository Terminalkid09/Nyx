from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from modules.sequencer.service import SequencerService

router = APIRouter(prefix="/api/sequencer", tags=["sequencer"])
sequencer = SequencerService()


class SequencerRequest(BaseModel):
    tokens: list[str]


class LiveCaptureRequest(BaseModel):
    session_id: str


class LiveCaptureTokenRequest(BaseModel):
    session_id: str
    token: str


@router.post("/analyze")
async def analyze_tokens(body: SequencerRequest):
    result = sequencer.analyze(body.tokens)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])
    return result


@router.post("/analyze-detailed")
async def analyze_detailed(body: SequencerRequest):
    result = sequencer.analyze(body.tokens)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])

    enhanced = {
        "sample_count": result["sample_count"],
        "token_length": result["token_length"],
        "char_entropy_bits_per_char": result["char_entropy_bits_per_char"],
        "estimated_total_bits": result["estimated_total_bits"],
        "bit_entropy": result["bit_entropy"],
        "verdict": result["verdict"],
        "is_weak": result["is_weak"],
        "unique_tokens": result["unique_tokens"],
        "duplicates_found": result["duplicates_found"],
        "character_set_size": result["character_set_size"],
        "unique_chars_ratio": result["unique_chars_ratio"],
        "predicted_token_type": result["predicted_token_type"],
        "effective_entropy": result["effective_entropy"],
        "consecutive_duplicate_percentage": result["consecutive_duplicate_percentage"],
        "longest_consecutive_run": result["longest_consecutive_run"],
        "char_frequencies": result["char_frequencies"],
        "positional_entropy": result["positional_entropy_detail"],
        "byte_distribution": result["byte_distribution_detail"],
        "autocorrelation": result["auto_correlation"]["lag_1"],
        "fips_140_2": result["fips_140_2"],
    }
    return enhanced


@router.post("/fips-140-2")
async def fips_140_2(body: SequencerRequest):
    result = sequencer.run_fips_140_2(body.tokens)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])
    return result


@router.post("/live/start")
async def live_start(body: LiveCaptureRequest):
    sequencer.start_live_capture(body.session_id)
    return {"status": "started", "session_id": body.session_id}


@router.post("/live/stop")
async def live_stop(body: LiveCaptureRequest):
    sequencer.stop_live_capture(body.session_id)
    return {"status": "stopped", "session_id": body.session_id}


@router.get("/live/tokens/{session_id}")
async def live_tokens(session_id: str):
    tokens = sequencer.get_live_tokens(session_id)
    return {"session_id": session_id, "tokens": tokens, "count": len(tokens)}


@router.post("/live/clear")
async def live_clear(body: LiveCaptureRequest):
    sequencer.clear_live_tokens(body.session_id)
    return {"status": "cleared", "session_id": body.session_id}


@router.get("/live/capturing/{session_id}")
async def live_status(session_id: str):
    return {"session_id": session_id, "is_capturing": sequencer.is_capturing(session_id)}


# --- New endpoints ---

class ChiSquareResponse(BaseModel):
    chi_square_statistic: float
    degrees_of_freedom: int
    p_value: float
    charset_size: int
    sample_size: int
    expected_per_char: float
    is_significant: bool
    interpretation: str


@router.post("/chi-square", response_model=ChiSquareResponse)
async def chi_square_analysis(body: SequencerRequest):
    result = sequencer.chi_square_analysis(body.tokens)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])
    return result


@router.post("/monte-carlo")
async def monte_carlo_simulation(body: SequencerRequest, trials: int = Query(1000, ge=100, le=100000)):
    result = sequencer.monte_carlo_simulation(body.tokens, trials=trials)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])
    return result


@router.post("/bit-analysis")
async def bit_analysis(body: SequencerRequest):
    result = sequencer.bit_analysis(body.tokens)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])
    return result


@router.post("/chart-data")
async def chart_data(body: SequencerRequest):
    result = sequencer.generate_chart_data(body.tokens)
    if "error" in result:
        raise HTTPException(400, detail=result["error"])
    return result
