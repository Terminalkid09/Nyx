from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.decoder.service import DecoderService

router = APIRouter(prefix="/api/decoder", tags=["decoder"])
decoder_service = DecoderService()


class DecodeRequest(BaseModel):
    input: str
    codec: str


class DecodeResponse(BaseModel):
    input: str
    codec: str
    output: str


class SmartDecodeRequest(BaseModel):
    input: str


class RecursiveDecodeRequest(BaseModel):
    input: str


class HashIdentifyRequest(BaseModel):
    hash: str


class HexDumpRequest(BaseModel):
    data: str


class CharsetDetectRequest(BaseModel):
    data: str


class JwtDecodeRequest(BaseModel):
    token: str


class HtmlEncodeRequest(BaseModel):
    input: str
    mode: str


class ConvertRequest(BaseModel):
    input: str
    from_encoding: str
    to_encoding: str


class HashRequest(BaseModel):
    input: str
    algorithm: str


class RecipeStep(BaseModel):
    codec: str


class RecipeRequest(BaseModel):
    input: str
    steps: list[RecipeStep]


@router.post("/transform", response_model=DecodeResponse)
async def transform(body: DecodeRequest):
    try:
        output = decoder_service.decode(body.input, body.codec)
        return DecodeResponse(input=body.input, codec=body.codec, output=output)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/smart-decode")
async def smart_decode(body: SmartDecodeRequest):
    try:
        results = decoder_service.smart_decode(body.input)
        return {"results": results}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/recursive-decode")
async def recursive_decode(body: RecursiveDecodeRequest):
    try:
        chain = decoder_service.recursive_smart_decode(body.input)
        return {"input": body.input, "chain": chain}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/hash-identify")
async def hash_identify(body: HashIdentifyRequest):
    try:
        results = decoder_service.hash_identifier(body.hash)
        return {"results": results}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/hex-dump")
async def hex_dump(body: HexDumpRequest):
    try:
        output = decoder_service.hex_dump(body.data)
        return {"output": output}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/charset-detect")
async def charset_detect(body: CharsetDetectRequest):
    try:
        result = decoder_service.charset_detect(body.data)
        return result
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/jwt-decode")
async def jwt_decode(body: JwtDecodeRequest):
    try:
        result = decoder_service.jwt_decode_full(body.token)
        return result
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/html-encode")
async def html_encode(body: HtmlEncodeRequest):
    try:
        if body.mode == "encode":
            output = decoder_service.html_encode_full(body.input)
        elif body.mode == "decode":
            output = decoder_service.html_decode_full(body.input)
        else:
            raise HTTPException(400, detail="mode must be 'encode' or 'decode'")
        return {"input": body.input, "mode": body.mode, "output": output}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/convert")
async def convert(body: ConvertRequest):
    try:
        output = decoder_service.convert_encoding(body.input, body.from_encoding, body.to_encoding)
        return {"input": body.input, "from_encoding": body.from_encoding, "to_encoding": body.to_encoding, "output": output}
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/hash")
async def hash_endpoint(body: HashRequest):
    try:
        output = decoder_service.hash_string(body.input, body.algorithm)
        return {"input": body.input, "algorithm": body.algorithm, "output": output}
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.post("/recipe")
async def process_recipe(body: RecipeRequest):
    try:
        chain = []
        current = body.input
        for i, step in enumerate(body.steps):
            output = decoder_service.decode(current, step.codec)
            chain.append({
                "step": i + 1,
                "codec": step.codec,
                "input": current,
                "output": output
            })
            current = output
        return {"input": body.input, "chain": chain, "final_output": current}
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=str(e))
