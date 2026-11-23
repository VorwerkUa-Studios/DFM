using CUE4Parse.UE4.Assets.Exports.Component.StaticMesh;
using CUE4Parse.UE4.Assets.Readers;
using CUE4Parse.UE4.Versions;
using Newtonsoft.Json;

public sealed class Stalker2InstancedStaticMeshComponent : UStaticMeshComponent
{
    public FInstancedStaticMeshInstanceData[]? PerInstanceSMData;
    public float[]? PerInstanceSMCustomData;
    public bool HasSerializedInstanceData;
    public int SerializedInstanceCount;
    public string? InstanceDataDecodeError;

    public override void Deserialize(FAssetArchive archive, long validPosition)
    {
        base.Deserialize(archive, validPosition);

        var isCooked = false;
        if (FFortniteMainBranchObjectVersion.Get(archive) >=
                FFortniteMainBranchObjectVersion.Type.SerializeInstancedStaticMeshRenderData ||
            FEditorObjectVersion.Get(archive) >= FEditorObjectVersion.Type.SerializeInstancedStaticMeshRenderData)
        {
            isCooked = archive.ReadBoolean();
        }

        var hasSkipSerializationData =
            FFortniteMainBranchObjectVersion.Get(archive) <
                FFortniteMainBranchObjectVersion.Type.ISMComponentEditableWhenInheritedSkipSerialization ||
            archive.ReadBoolean();
        if (hasSkipSerializationData)
        {
            HasSerializedInstanceData = true;
            archive.Position += sizeof(int);
            var instanceCount = archive.Read<int>();
            if (instanceCount < 0 || instanceCount > 10_000_000)
                throw new InvalidDataException($"Invalid STALKER 2 instance count: {instanceCount}.");
            SerializedInstanceCount = instanceCount;

            var availableBytes = validPosition - archive.Position;
            var requiredBytes = (long)instanceCount * 128;
            if (requiredBytes > availableBytes)
            {
                InstanceDataDecodeError =
                    $"Serialized instance array needs {requiredBytes} bytes, but only {Math.Max(0, availableBytes)} bytes remain in this export.";
                return;
            }

            PerInstanceSMData = archive.ReadBulkArray(
                128,
                instanceCount,
                () => new FInstancedStaticMeshInstanceData(archive));
            if (FRenderingObjectVersion.Get(archive) >= FRenderingObjectVersion.Type.PerInstanceCustomData)
                PerInstanceSMCustomData = archive.ReadBulkArray(archive.Read<float>);
        }

        if (!isCooked ||
            (FFortniteMainBranchObjectVersion.Get(archive) <
                 FFortniteMainBranchObjectVersion.Type.SerializeInstancedStaticMeshRenderData &&
             FEditorObjectVersion.Get(archive) <
                 FEditorObjectVersion.Type.SerializeInstancedStaticMeshRenderData) ||
            archive.Game < EGame.GAME_UE5_4)
        {
            return;
        }

        if (!archive.ReadBoolean())
            return;
        archive.SkipBulkArrayData();
        archive.SkipBulkArrayData();
    }

    protected override void WriteJson(JsonWriter writer, JsonSerializer serializer)
    {
        base.WriteJson(writer, serializer);
        if (PerInstanceSMData is { Length: > 0 })
        {
            writer.WritePropertyName(nameof(PerInstanceSMData));
            serializer.Serialize(writer, PerInstanceSMData);
        }

        if (PerInstanceSMCustomData is { Length: > 0 })
        {
            writer.WritePropertyName(nameof(PerInstanceSMCustomData));
            serializer.Serialize(writer, PerInstanceSMCustomData);
        }

        writer.WritePropertyName(nameof(HasSerializedInstanceData));
        writer.WriteValue(HasSerializedInstanceData);
        writer.WritePropertyName(nameof(SerializedInstanceCount));
        writer.WriteValue(SerializedInstanceCount);
        if (InstanceDataDecodeError is not null)
        {
            writer.WritePropertyName(nameof(InstanceDataDecodeError));
            writer.WriteValue(InstanceDataDecodeError);
        }
    }
}
